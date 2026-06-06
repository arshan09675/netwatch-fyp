"""
NetWatch GeoIP Module - Advanced IP Intelligence
Supports: MaxMind GeoLite2 (offline), ip-api.com (free), ipinfo.io (token)
"""

import os
import json
import asyncio
import aiohttp
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, field
from functools import lru_cache
from datetime import datetime, timedelta
import socket
import logging

# Try to import MaxMind GeoIP2 library
try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    print("[GeoIP] geoip2 not installed. Install with: pip install geoip2")

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

# Database file paths
GEOIP_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")
ASN_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-ASN.mmdb")

# Cache for API responses (5 minutes)
CACHE_DURATION = timedelta(minutes=5)

@dataclass
class GeoLocation:
    """Complete geolocation data structure"""
    ip: str
    country_code: str = ""
    country_name: str = ""
    city: str = ""
    region: str = ""
    postal_code: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    isp: str = ""
    organization: str = ""
    asn: str = ""
    as_name: str = ""
    is_proxy: bool = False
    is_mobile: bool = False
    risk_score: float = 0.0
    source: str = "unknown"
    
    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "region": self.region,
            "postal_code": self.postal_code,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "isp": self.isp,
            "organization": self.organization,
            "asn": self.asn,
            "as_name": self.as_name,
            "is_proxy": self.is_proxy,
            "is_mobile": self.is_mobile,
            "risk_score": self.risk_score,
            "source": self.source
        }
    
    def get_map_marker(self) -> dict:
        """Get data formatted for map visualization"""
        return {
            "lat": self.latitude,
            "lng": self.longitude,
            "title": f"{self.city}, {self.country_name}",
            "ip": self.ip,
            "isp": self.isp
        }


class GeoIPService:
    """
    Advanced GeoIP Service with multiple data sources
    Priority: MaxMind DB > ip-api.com > ipinfo.io (if token)
    """
    
    def __init__(self):
        self.reader_city = None
        self.reader_asn = None
        self.cache: Dict[str, tuple] = {}  # ip -> (timestamp, GeoLocation)
        self._load_maxmind_db()
    
    def _load_maxmind_db(self):
        """Load MaxMind GeoLite2 databases if available"""
        if GEOIP2_AVAILABLE:
            if os.path.exists(GEOIP_DB_PATH):
                try:
                    self.reader_city = geoip2.database.Reader(GEOIP_DB_PATH)
                    print(f"[GeoIP] Loaded MaxMind City DB: {GEOIP_DB_PATH}")
                except Exception as e:
                    print(f"[GeoIP] Failed to load City DB: {e}")
            
            if os.path.exists(ASN_DB_PATH):
                try:
                    self.reader_asn = geoip2.database.Reader(ASN_DB_PATH)
                    print(f"[GeoIP] Loaded MaxMind ASN DB: {ASN_DB_PATH}")
                except Exception as e:
                    print(f"[GeoIP] Failed to load ASN DB: {e}")
    
    def _is_cached_valid(self, ip: str) -> Optional[GeoLocation]:
        """Check if cached data is still valid"""
        if ip in self.cache:
            timestamp, data = self.cache[ip]
            if datetime.now() - timestamp < CACHE_DURATION:
                return data
        return None
    
    def _cache_set(self, ip: str, data: GeoLocation):
        """Store in cache"""
        self.cache[ip] = (datetime.now(), data)
    
    def _get_from_maxmind(self, ip: str) -> Optional[GeoLocation]:
        """Get geolocation from local MaxMind database"""
        if not self.reader_city:
            return None
        
        try:
            # Skip private/local IPs
            if ip.startswith(('10.', '172.16.', '192.168.', '127.', '169.254.')):
                return None
            
            response = self.reader_city.city(ip)
            
            location = GeoLocation(
                ip=ip,
                country_code=response.country.iso_code or "",
                country_name=response.country.name or "",
                city=response.city.name or "",
                region=response.subdivisions.most_specific.name or "",
                postal_code=response.postal.code or "",
                latitude=response.location.latitude or 0.0,
                longitude=response.location.longitude or 0.0,
                timezone=response.location.time_zone or "",
                source="maxmind"
            )
            
            # Get ASN info if available
            if self.reader_asn:
                try:
                    asn_response = self.reader_asn.asn(ip)
                    location.asn = str(asn_response.autonomous_system_number)
                    location.as_name = asn_response.autonomous_system_organization or ""
                except AddressNotFoundError:
                    pass
            
            return location
            
        except AddressNotFoundError:
            return None
        except Exception as e:
            print(f"[GeoIP] MaxMind error for {ip}: {e}")
            return None
    
    async def _get_from_ipapi(self, ip: str) -> Optional[GeoLocation]:
        """Get geolocation from ip-api.com (free, no token needed)"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,regionName,zip,lat,lon,timezone,isp,org,as,mobile,proxy,query"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        if data.get('status') == 'success':
                            return GeoLocation(
                                ip=data.get('query', ip),
                                country_code=data.get('countryCode', ''),
                                country_name=data.get('country', ''),
                                city=data.get('city', ''),
                                region=data.get('regionName', ''),
                                postal_code=data.get('zip', ''),
                                latitude=data.get('lat', 0.0),
                                longitude=data.get('lon', 0.0),
                                timezone=data.get('timezone', ''),
                                isp=data.get('isp', ''),
                                organization=data.get('org', ''),
                                asn=data.get('as', '').split(' ')[0] if data.get('as') else '',
                                is_proxy=data.get('proxy', False),
                                is_mobile=ip.startswith(('10.', '172.')),  # Approximate
                                source="ip-api.com"
                            )
        except Exception as e:
            print(f"[GeoIP] ip-api.com error for {ip}: {e}")
        
        return None
    
    async def _get_from_ipinfo(self, ip: str, token: str = "") -> Optional[GeoLocation]:
        """Get geolocation from ipinfo.io (requires token for production)"""
        if not token:
            token = os.getenv("IPINFO_TOKEN", "")
        
        if not token:
            return None
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://ipinfo.io/{ip}/json?token={token}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        # Parse location (lat,lng)
                        loc = data.get('loc', '').split(',')
                        lat = float(loc[0]) if len(loc) > 0 else 0.0
                        lng = float(loc[1]) if len(loc) > 1 else 0.0
                        
                        return GeoLocation(
                            ip=data.get('ip', ip),
                            country_code=data.get('country', ''),
                            city=data.get('city', ''),
                            region=data.get('region', ''),
                            latitude=lat,
                            longitude=lng,
                            timezone=data.get('timezone', ''),
                            isp=data.get('org', '').split(' ')[0] if data.get('org') else '',
                            organization=data.get('org', ''),
                            source="ipinfo.io"
                        )
        except Exception as e:
            print(f"[GeoIP] ipinfo.io error for {ip}: {e}")
        
        return None
    
    async def get_location(self, ip: str, prefer_local: bool = True) -> GeoLocation:
        """
        Get geolocation for an IP address
        Priority: Cache > MaxMind > ip-api.com > ipinfo.io
        """
        # Validate IP
        try:
            socket.inet_aton(ip)
        except socket.error:
            return GeoLocation(ip=ip, source="invalid")
        
        # Check cache first
        cached = self._is_cached_valid(ip)
        if cached:
            return cached
        
        # Local/Private IPs
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                         '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                         '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                         '172.30.', '172.31.', '192.168.', '127.', '169.254.')):
            location = GeoLocation(
                ip=ip,
                country_name="Local Network",
                country_code="LOCAL",
                city="Private IP",
                source="private"
            )
            self._cache_set(ip, location)
            return location
        
        location = None
        
        # Try MaxMind first (fastest, offline)
        if prefer_local:
            location = self._get_from_maxmind(ip)
        
        # Fallback to ip-api.com
        if location is None:
            location = await self._get_from_ipapi(ip)
        
        # Final fallback to ipinfo.io
        if location is None:
            location = await self._get_from_ipinfo(ip)
        
        # If all failed, return basic info
        if location is None:
            location = GeoLocation(ip=ip, source="none")
        
        # Cache result
        self._cache_set(ip, location)
        
        return location
    
    async def get_batch_locations(self, ips: List[str]) -> List[GeoLocation]:
        """Get locations for multiple IPs concurrently"""
        tasks = [self.get_location(ip) for ip in ips]
        return await asyncio.gather(*tasks)
    
    def get_risk_score(self, ip: str) -> float:
        """
        Calculate risk score for an IP (0-100)
        Higher score = more suspicious
        """
        score = 0.0
        
        # Known proxy/datacenter IPs (simplified)
        proxy_ranges = [
            ('104.16.0.0', '104.31.255.255'),  # Cloudflare
            ('34.0.0.0', '34.127.255.255'),    # Google Cloud
        ]
        
        # Check if IP is in proxy ranges
        ip_int = self._ip_to_int(ip)
        for start, end in proxy_ranges:
            if self._ip_to_int(start) <= ip_int <= self._ip_to_int(end):
                score += 50
        
        # TOR exit nodes (simplified - would need live list)
        if ip.startswith('5.') or ip.startswith('185.'):
            score += 30
        
        # High risk countries
        high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'SY', 'UA']
        
        # We'll need async for country check, so this is placeholder
        return min(100, score)
    
    def _ip_to_int(self, ip: str) -> int:
        """Convert IP to integer for range comparison"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


# Singleton instance
geoip_service = GeoIPService()


# FastAPI Routes for GeoIP
def register_geoip_routes(app):
    """Register GeoIP routes with FastAPI app"""
    
    @app.get("/api/geoip/{ip}")
    async def get_geoip(ip: str):
        """Get geolocation for a specific IP"""
        location = await geoip_service.get_location(ip)
        return location.to_dict()
    
    @app.get("/api/geoip/batch")
    async def get_geoip_batch(ips: str):
        """Get geolocation for multiple IPs (comma-separated)"""
        ip_list = [ip.strip() for ip in ips.split(',')]
        locations = await geoip_service.get_batch_locations(ip_list)
        return [loc.to_dict() for loc in locations]
    
    @app.get("/api/geoip/myip")
    async def get_my_ip(request):
        """Get geolocation for client's IP"""
        client_ip = request.client.host if request.client else "unknown"
        location = await geoip_service.get_location(client_ip)
        return location.to_dict()
    
    @app.get("/api/geoip/stats")
    async def get_geoip_stats():
        """Get GeoIP service statistics"""
        return {
            "maxmind_available": geoip_service.reader_city is not None,
            "cache_size": len(geoip_service.cache),
            "sources": ["maxmind", "ip-api.com", "ipinfo.io"]
        }