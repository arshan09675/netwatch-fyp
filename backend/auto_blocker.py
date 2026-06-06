"""
AUTO THREAT BLOCKER - Automatically blocks malicious IPs
"""

import subprocess
import time
from collections import defaultdict
import os
import aiohttp
import asyncio

class AutoBlocker:
    """Automatic threat blocking system with AbuseIPDB integration"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.threat_scores = defaultdict(int)
        self.block_history = []
        self.enabled = True
        self.threshold = 70
        
        # ✅ API Key Added
        self.abuseipdb_key = "034911d5fe7c4072bc2e3fae25debfc4f0eef6c957e806683dff05eeb127713b39cb4896ca07e896"
        
        # Fallback to environment variable
        if not self.abuseipdb_key:
            self.abuseipdb_key = os.getenv("ABUSEIPDB_KEY", "")
        
        if self.abuseipdb_key:
            print(f"[AutoBlocker] ✅ AbuseIPDB configured")
        else:
            print(f"[AutoBlocker] ⚠️ AbuseIPDB not configured")
    
    async def check_abuseipdb(self, ip: str) -> int:
        """Check IP reputation using AbuseIPDB API"""
        if not self.abuseipdb_key:
            return 0
        
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json"
                }
                params = {
                    "ipAddress": ip,
                    "maxAgeInDays": 90
                }
                
                async with session.get(url, headers=headers, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        score = data.get("data", {}).get("abuseConfidenceScore", 0)
                        print(f"[AutoBlocker] AbuseIPDB score for {ip}: {score}%")
                        return score
                    else:
                        print(f"[AutoBlocker] AbuseIPDB API error: {resp.status}")
        except Exception as e:
            print(f"[AutoBlocker] AbuseIPDB error: {e}")
        
        return 0
    
    def block(self, ip, reason):
        """Block IP using Windows Firewall"""
        if ip in self.blocked_ips:
            return False
        
        try:
            rule_name = f"NetWatch_Block_{ip.replace('.', '_')}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}', 'dir=in', f'remoteip={ip}',
                'protocol=any', 'action=block'
            ], capture_output=True, timeout=5)
            
            self.blocked_ips.add(ip)
            self.block_history.append({
                'timestamp': time.time(),
                'ip': ip,
                'reason': reason
            })
            print(f"[AutoBlocker] 🔒 Blocked: {ip} - {reason}")
            return True
        except Exception as e:
            print(f"[AutoBlocker] Block failed: {e}")
            return False
    
    def unblock(self, ip):
        """Unblock IP"""
        if ip not in self.blocked_ips:
            return False
        
        try:
            rule_name = f"NetWatch_Block_{ip.replace('.', '_')}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}'
            ], capture_output=True, timeout=5)
            
            self.blocked_ips.remove(ip)
            print(f"[AutoBlocker] 🔓 Unblocked: {ip}")
            return True
        except:
            return False
    
    def report_threat(self, ip, score, reason):
        """Report threat and auto-block if needed"""
        self.threat_scores[ip] += score
        
        if self.enabled and self.threat_scores[ip] >= self.threshold:
            if ip not in self.blocked_ips:
                self.block(ip, reason)
                return {'blocked': True, 'ip': ip}
        
        return {'blocked': False, 'score': self.threat_scores[ip]}
    
    async def check_and_block(self, ip: str, reason: str = "Suspicious activity"):
        """Check IP with AbuseIPDB and block if malicious"""
        # First check local scores
        if self.threat_scores[ip] >= self.threshold:
            return self.block(ip, reason)
        
        # Check AbuseIPDB
        abuse_score = await self.check_abuseipdb(ip)
        
        if abuse_score >= 70:
            self.report_threat(ip, abuse_score, f"AbuseIPDB score: {abuse_score}% - {reason}")
            return True
        elif abuse_score >= 30:
            print(f"[AutoBlocker] ⚠️ Suspicious IP: {ip} (score: {abuse_score}%)")
        
        return False
    
    def get_status(self):
        return {
            'blocked': list(self.blocked_ips),
            'total': len(self.blocked_ips),
            'enabled': self.enabled,
            'history': self.block_history[-10:][::-1],
            'abuseipdb_configured': bool(self.abuseipdb_key)
        }

auto_blocker = AutoBlocker()