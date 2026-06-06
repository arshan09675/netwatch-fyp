"""
LIVE WEBSITE TRACKER - Real-time website monitoring
Shows which websites are being visited and their bandwidth usage
"""

import socket
import time
import threading
from collections import defaultdict
import json

class WebsiteTracker:
    """Complete website tracking with categories, real-time updates, and analytics"""
    
    def __init__(self):
        self.websites = {}
        self.ip_cache = {}
        self.lock = threading.Lock()
        self.category_db = self._load_categories()
        
    def _load_categories(self):
        """Complete website categorization database"""
        return {
            # Streaming
            'youtube.com': '🎬 Streaming', 'youtu.be': '🎬 Streaming',
            'netflix.com': '🎬 Streaming', 'primevideo.com': '🎬 Streaming',
            'hotstar.com': '🎬 Streaming', 'disneyplus.com': '🎬 Streaming',
            'twitch.tv': '🎮 Gaming/Streaming',
            
            # Social Media
            'facebook.com': '📱 Social', 'instagram.com': '📱 Social',
            'twitter.com': '📱 Social', 'tiktok.com': '📱 Social',
            'reddit.com': '📱 Social', 'linkedin.com': '💼 Business',
            'whatsapp.com': '💬 Messaging', 'telegram.org': '💬 Messaging',
            'discord.com': '💬 Messaging',
            
            # Search & AI
            'google.com': '🔍 Search', 'bing.com': '🔍 Search',
            'chat.openai.com': '🤖 AI', 'chatgpt.com': '🤖 AI',
            'claude.ai': '🤖 AI', 'gemini.google.com': '🤖 AI',
            'deepseek.com': '🤖 AI',
            
            # Shopping
            'amazon.com': '🛒 Shopping', 'daraz.pk': '🛒 Shopping',
            'ebay.com': '🛒 Shopping', 'aliexpress.com': '🛒 Shopping',
            'walmart.com': '🛒 Shopping',
            
            # Development
            'github.com': '💻 Dev', 'stackoverflow.com': '💻 Dev',
            'gitlab.com': '💻 Dev', 'docs.python.org': '💻 Dev',
            
            # Gaming
            'steam.com': '🎮 Gaming', 'roblox.com': '🎮 Gaming',
            'epicgames.com': '🎮 Gaming', 'minecraft.net': '🎮 Gaming',
            
            # Email
            'gmail.com': '📧 Email', 'outlook.com': '📧 Email',
            
            # Cloud
            'drive.google.com': '☁️ Cloud', 'dropbox.com': '☁️ Cloud',
            'onedrive.live.com': '☁️ Cloud',
        }
    
    def get_domain(self, ip):
        """Resolve IP to domain with caching"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            parts = hostname.lower().split('.')
            if len(parts) >= 2:
                domain = '.'.join(parts[-2:])
            else:
                domain = hostname
            self.ip_cache[ip] = domain
            return domain
        except:
            self.ip_cache[ip] = ip
            return ip
    
    def get_category(self, domain):
        """Get category for domain"""
        domain_lower = domain.lower()
        for key, category in self.category_db.items():
            if key in domain_lower:
                return category
        return '🌐 Other'
    
    def update_from_connections(self, connections):
        """Update website data from live connections"""
        with self.lock:
            # Reset counters
            for site in self.websites:
                self.websites[site]['connections'] = 0
            
            current_time = time.time()
            
            for conn in connections:
                remote_ip = conn.get('remote_ip', '')
                if not remote_ip:
                    continue
                
                # Skip local IPs
                if remote_ip.startswith(('127.', '192.168.', '10.', '172.', '169.254.')):
                    continue
                
                domain = self.get_domain(remote_ip)
                category = self.get_category(domain)
                process = conn.get('process', 'unknown')
                
                if domain not in self.websites:
                    self.websites[domain] = {
                        'domain': domain,
                        'category': category,
                        'connections': 0,
                        'first_seen': current_time,
                        'last_seen': current_time,
                        'processes': set(),
                        'total_connections': 0
                    }
                
                self.websites[domain]['connections'] += 1
                self.websites[domain]['total_connections'] += 1
                self.websites[domain]['last_seen'] = current_time
                self.websites[domain]['processes'].add(process)
            
            # Clean old (2 minutes)
            to_remove = []
            for domain, info in self.websites.items():
                if current_time - info['last_seen'] > 120:
                    to_remove.append(domain)
            for domain in to_remove:
                del self.websites[domain]
            
            return self.get_stats()
    
    def get_stats(self):
        """Get complete website statistics"""
        active_sites = []
        category_stats = defaultdict(lambda: {'count': 0, 'connections': 0})
        
        for domain, info in self.websites.items():
            if info['connections'] > 0:
                active_sites.append({
                    'domain': info['domain'],
                    'category': info['category'],
                    'connections': info['connections'],
                    'total_connections': info['total_connections'],
                    'processes': list(info['processes'])[:3]
                })
                category_stats[info['category']]['count'] += 1
                category_stats[info['category']]['connections'] += info['connections']
        
        active_sites.sort(key=lambda x: x['connections'], reverse=True)
        
        return {
            'total_active': len(active_sites),
            'top_sites': active_sites[:20],
            'category_breakdown': dict(category_stats),
            'timestamp': time.time()
        }

website_tracker = WebsiteTracker()