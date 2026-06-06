"""
NetWatch Advanced Threat Intelligence Module
- Malicious IP Detection (AbuseIPDB + Local DB)
- IP Reputation Scoring
- Auto Blocking
- Real-time Threat Feed
"""

import os
import json
import aiohttp
import asyncio
import socket
import time  # ✅ Added missing import
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict

# ============================================
# LOCAL THREAT DATABASE
# ============================================

# Known malicious IPs with categories
MALICIOUS_IPS = {
    "185.130.5.253": {"category": "DDoS Botnet", "severity": "critical", "confidence": 95},
    "45.155.205.233": {"category": "Port Scanner", "severity": "high", "confidence": 85},
    "94.102.61.78": {"category": "C2 Server", "severity": "critical", "confidence": 98},
    "185.244.211.34": {"category": "Brute Force", "severity": "high", "confidence": 90},
    "45.146.164.100": {"category": "Malware Distribution", "severity": "critical", "confidence": 92},
    "185.174.137.26": {"category": "Cryptominer", "severity": "medium", "confidence": 75},
    "81.17.31.48": {"category": "Phishing", "severity": "high", "confidence": 88},
    "194.87.235.146": {"category": "Scanning", "severity": "medium", "confidence": 70},
    "91.92.241.133": {"category": "Spam", "severity": "low", "confidence": 65},
    "45.88.221.33": {"category": "Exploit Attempt", "severity": "high", "confidence": 85},
}

# Suspicious IPs (monitoring)
SUSPICIOUS_IPS = {
    "45.33.32.156": "Suspicious Scanner",
    "185.250.151.204": "Brute Force Attempt", 
    "185.161.108.92": "Malicious Request",
}

# Malicious port patterns
MALICIOUS_PORTS = {
    22: "SSH Brute Force",
    23: "Telnet Attack",
    445: "SMB/Ransomware",
    3389: "RDP Attack",
    1433: "SQL Server Attack",
    3306: "MySQL Attack",
    5432: "PostgreSQL Attack",
    6379: "Redis Attack",
    27017: "MongoDB Attack",
}

@dataclass
class ThreatIntel:
    ip: str
    is_malicious: bool
    is_suspicious: bool
    threat_score: int
    category: str
    severity: str
    source: str
    details: str
    timestamp: float = field(default_factory=time.time)

class AdvancedThreatIntel:
    def __init__(self):
        self.cache: Dict[str, ThreatIntel] = {}
        self.threat_history: List[ThreatIntel] = []
        self.alert_callback = None
        self.blocked_ips: set = set()
        
        # API Keys (set via environment)
        self.abuseipdb_key = os.getenv("ABUSEIPDB_KEY", "")
        self.virustotal_key = os.getenv("VIRUSTOTAL_KEY", "")
        self.iptelemetry_key = os.getenv("IPTELEMETRY_KEY", "")
    
    def check_local_threats(self, ip: str) -> Optional[ThreatIntel]:
        """Check local threat database"""
        
        # Check malicious IPs
        if ip in MALICIOUS_IPS:
            data = MALICIOUS_IPS[ip]
            return ThreatIntel(
                ip=ip,
                is_malicious=True,
                is_suspicious=False,
                threat_score=data["confidence"],
                category=data["category"],
                severity=data["severity"],
                source="local_threat_db",
                details=f"Known {data['category']} (confidence: {data['confidence']}%)"
            )
        
        # Check suspicious IPs
        if ip in SUSPICIOUS_IPS:
            return ThreatIntel(
                ip=ip,
                is_malicious=False,
                is_suspicious=True,
                threat_score=50,
                category="suspicious",
                severity="medium",
                source="local_threat_db",
                details=SUSPICIOUS_IPS[ip]
            )
        
        # Private IPs
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                         '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                         '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                         '172.30.', '172.31.', '192.168.', '127.', '169.254.')):
            return ThreatIntel(
                ip=ip,
                is_malicious=False,
                is_suspicious=False,
                threat_score=0,
                category="private",
                severity="info",
                source="local",
                details="Internal network IP"
            )
        
        return None
    
    async def check_abuseipdb(self, ip: str) -> Optional[ThreatIntel]:
        """Check AbuseIPDB API for reputation"""
        if not self.abuseipdb_key:
            return None
        
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
                params = {"ipAddress": ip, "maxAgeInDays": 90}
                
                async with session.get(url, headers=headers, params=params, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = data.get("data", {})
                        score = result.get("abuseConfidenceScore", 0)
                        
                        if score >= 80:
                            return ThreatIntel(
                                ip=ip, is_malicious=True, is_suspicious=False,
                                threat_score=score, category="malicious",
                                severity="critical", source="abuseipdb",
                                details=f"AbuseIPDB score: {score}%"
                            )
                        elif score >= 40:
                            return ThreatIntel(
                                ip=ip, is_malicious=False, is_suspicious=True,
                                threat_score=score, category="suspicious",
                                severity="medium", source="abuseipdb",
                                details=f"Suspicious (score: {score}%)"
                            )
        except Exception as e:
            print(f"[ThreatIntel] AbuseIPDB error: {e}")
        
        return None
    
    async def check_ip_reputation(self, ip: str) -> ThreatIntel:
        """Comprehensive IP reputation check"""
        
        # Check cache
        if ip in self.cache:
            cached = self.cache[ip]
            if time.time() - cached.timestamp < 600:  # 10 min cache
                return cached
        
        # Local check first
        local_result = self.check_local_threats(ip)
        if local_result and local_result.is_malicious:
            self.cache[ip] = local_result
            self.threat_history.append(local_result)
            return local_result
        
        # External API check
        external_result = await self.check_abuseipdb(ip)
        if external_result:
            self.cache[ip] = external_result
            if external_result.is_malicious:
                self.threat_history.append(external_result)
            return external_result
        
        # Clean IP
        result = ThreatIntel(
            ip=ip, is_malicious=False, is_suspicious=False,
            threat_score=0, category="clean", severity="info",
            source="default", details="No threats detected"
        )
        self.cache[ip] = result
        return result
    
    def check_connection_threat(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[ThreatIntel]:
        """Check if a connection is potentially malicious"""
        
        # Check destination port
        if dst_port in MALICIOUS_PORTS:
            return ThreatIntel(
                ip=dst_ip,
                is_malicious=True,
                is_suspicious=False,
                threat_score=70,
                category=MALICIOUS_PORTS[dst_port],
                severity="high",
                source="port_analysis",
                details=f"Suspicious connection to port {dst_port} ({MALICIOUS_PORTS[dst_port]})"
            )
        
        return None
    
    def get_threat_stats(self) -> dict:
        """Get threat intelligence statistics"""
        malicious_count = sum(1 for t in self.threat_history if t.is_malicious)
        suspicious_count = sum(1 for t in self.threat_history if t.is_suspicious)
        
        return {
            "total_threats": len(self.threat_history),
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "blocked_ips": len(self.blocked_ips),
            "cache_size": len(self.cache),
            "abuseipdb_enabled": bool(self.abuseipdb_key)
        }

# Singleton
threat_intel = AdvancedThreatIntel()