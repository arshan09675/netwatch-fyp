"""
DARK WEB DETECTOR - Detects dark web and suspicious connections
"""

import socket
import time
import re

class DarkWebDetector:
    """Complete dark web and threat detection system"""
    
    def __init__(self):
        self.darkweb_patterns = [
            '.onion', '.i2p', '.bit', '.tor', 'torproject.org',
            'tor2web.org', 'onion.link', 'onion.city'
        ]
        
        self.suspicious_ports = [22, 23, 445, 3389, 5900, 6667, 1337, 4444, 8080]
        
        self.high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'SY']
        
        self.detections = []
        
        # Malicious IP database
        self.malicious_ips = {
            '185.130.5.253': 'DDoS Botnet',
            '45.155.205.233': 'Port Scanner',
            '94.102.61.78': 'C2 Server',
            '185.244.211.34': 'Brute Force',
        }
    
    def scan(self, ip, port):
        """Scan connection for dark web indicators"""
        result = {
            'is_darkweb': False,
            'is_malicious': False,
            'risk_level': 'low',
            'reason': None,
            'ip': ip,
            'port': port
        }
        
        # Check malicious IP database
        if ip in self.malicious_ips:
            result['is_malicious'] = True
            result['risk_level'] = 'critical'
            result['reason'] = f"Known malicious IP: {self.malicious_ips[ip]}"
            return result
        
        # Check suspicious ports
        if port in self.suspicious_ports:
            result['is_malicious'] = True
            result['risk_level'] = 'high'
            result['reason'] = f"Suspicious port: {port}"
        
        # Try to resolve domain
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            for pattern in self.darkweb_patterns:
                if pattern in hostname:
                    result['is_darkweb'] = True
                    result['risk_level'] = 'critical'
                    result['reason'] = f"Dark web: {hostname}"
                    break
        except:
            pass
        
        return result
    
    def add_detection(self, detection):
        """Add to detection history"""
        detection['timestamp'] = time.time()
        self.detections.append(detection)
        if len(self.detections) > 100:
            self.detections.pop(0)
    
    def get_recent(self, limit=50):
        """Get recent detections"""
        return self.detections[-limit:][::-1]

darkweb_detector = DarkWebDetector()