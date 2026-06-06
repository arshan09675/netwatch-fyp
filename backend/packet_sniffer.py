"""
NetWatch Advanced Packet Sniffer Module
Real-time packet capture and analysis using Scapy
"""

import time
import threading
import socket
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
import os

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
    print("[Sniffer] Scapy loaded successfully")
except ImportError:
    SCAPY_AVAILABLE = False
    print("[Sniffer] Scapy not installed. Packet sniffing disabled.")

from advanced_packet_stream import packet_stream

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class AdvancedPacketSniffer:
    def __init__(self, interface: str = None):
        self.interface = 'Wi-Fi'  # Force Wi-Fi interface
        self.sniffing = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = None
        
        self.protocol_stats = {
            "tcp": 0, "udp": 0, "icmp": 0, "arp": 0,
            "dns": 0, "http": 0, "https": 0, "other": 0
        }
        
        self.ip_stats: Dict[str, Dict] = defaultdict(lambda: {
            "bytes_sent": 0, "bytes_recv": 0,
            "packets": 0, "first_seen": 0, "last_seen": 0
        })
        
        self.recent_packets: List[Dict] = []
        self.port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self.alert_callback = None
        self.pcap_file = None
        self.bpf_filter = "ip"
    
    def _get_active_interface(self) -> str:
        """Auto-detect active interface"""
        if not PSUTIL_AVAILABLE:
            return 'Wi-Fi'
        
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            
            for name, stat in stats.items():
                if stat.isup:
                    for addr in addrs.get(name, []):
                        if addr.family == socket.AF_INET and addr.address:
                            ip = addr.address
                            if not ip.startswith('127.'):
                                print(f"[Sniffer] ✅ Found: {name} ({ip})")
                                return name
        except Exception as e:
            print(f"[Sniffer] Error: {e}")
        
        return 'Wi-Fi'
    
    def _extract_packet_info(self, packet) -> Optional[Dict]:
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                timestamp = time.time()
                size = len(packet)
                
                if packet.haslayer(TCP):
                    protocol = 'tcp'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    protocol = 'udp'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                else:
                    protocol = 'other'
                    src_port = 0
                    dst_port = 0
                
                return {
                    "timestamp": timestamp,
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "size": size,
                    "ttl": ip_layer.ttl,
                    "info": f"{protocol} packet"
                }
        except:
            pass
        return None
    
    def _update_stats(self, packet_info: Dict):
        self.packet_count += 1
        self.byte_count += packet_info["size"]
        
        proto = packet_info["protocol"]
        if proto in self.protocol_stats:
            self.protocol_stats[proto] += 1
        else:
            self.protocol_stats["other"] += 1
        
        src = packet_info["src_ip"]
        if self.ip_stats[src]["first_seen"] == 0:
            self.ip_stats[src]["first_seen"] = packet_info["timestamp"]
        self.ip_stats[src]["last_seen"] = packet_info["timestamp"]
        self.ip_stats[src]["bytes_sent"] += packet_info["size"]
        self.ip_stats[src]["packets"] += 1
        
        dst = packet_info["dst_ip"]
        if self.ip_stats[dst]["first_seen"] == 0:
            self.ip_stats[dst]["first_seen"] = packet_info["timestamp"]
        self.ip_stats[dst]["last_seen"] = packet_info["timestamp"]
        self.ip_stats[dst]["bytes_recv"] += packet_info["size"]
        self.ip_stats[dst]["packets"] += 1
        
        self.recent_packets.insert(0, packet_info)
        if len(self.recent_packets) > 100:
            self.recent_packets.pop()
    
    def _packet_handler(self, packet):
        if not self.sniffing:
            return
        
        packet_info = self._extract_packet_info(packet)
        if packet_info:
            self._update_stats(packet_info)
            packet_stream.add_packet(packet_info)

            # Buffer the REAL raw frame bytes so /api/packets/export/pcap can
            # produce a Wireshark-valid file (not fabricated text).
            try:
                packet_stream.buffer_raw(packet_info["timestamp"], bytes(packet))
            except Exception:
                pass

            if self.pcap_file:
                try:
                    self.pcap_file.write(packet)
                except:
                    pass
    
    def start_sniffing(self, count: int = 0, timeout: int = None, alert_callback=None):
        if not SCAPY_AVAILABLE:
            print("[Sniffer] Scapy not available")
            return False
        
        if self.sniffing:
            return False
        
        self.sniffing = True
        self.start_time = time.time()
        self.alert_callback = alert_callback
        
        def sniff_thread():
            try:
                print(f"[Sniffer] 🚀 Starting capture on: {self.interface}")
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    count=count,
                    timeout=timeout,
                    filter=self.bpf_filter
                )
            except Exception as e:
                print(f"[Sniffer] Error: {e}")
            finally:
                self.sniffing = False
        
        self.sniffer_thread = threading.Thread(target=sniff_thread, daemon=True)
        self.sniffer_thread.start()
        return True
    
    def stop_sniffing(self):
        self.sniffing = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
    
    def start_pcap_capture(self, filename: str = None):
        if not SCAPY_AVAILABLE:
            return None
        if filename is None:
            filename = f"data/capture_{int(time.time())}.pcap"
        os.makedirs("data", exist_ok=True)
        self.pcap_file = PcapWriter(filename, append=False, sync=True)
        return filename
    
    def get_stats(self) -> dict:
        duration = time.time() - self.start_time if self.start_time else 1
        mbps = (self.byte_count * 8) / (duration * 1_000_000) if duration > 0 else 0
        pps = self.packet_count / duration if duration > 0 else 0
        
        return {
            "is_sniffing": self.sniffing,
            "interface": self.interface,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration_seconds": round(duration, 2),
            "mbps": round(mbps, 2),
            "packets_per_second": round(pps, 2),
            "protocols": self.protocol_stats.copy(),
            "active_ips": len(self.ip_stats)
        }
    
    def get_recent_packets(self, limit: int = 50) -> List[dict]:
        return self.recent_packets[:limit]
    
    def clear_stats(self):
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = None
        self.protocol_stats = {k: 0 for k in self.protocol_stats}
        self.ip_stats.clear()
        self.recent_packets.clear()
    
    def set_filter(self, filter_string: str):
        self.bpf_filter = filter_string


packet_sniffer = AdvancedPacketSniffer()


def register_sniffer_routes(app):
    @app.get("/api/sniffer/status")
    async def sniffer_status():
        return packet_sniffer.get_stats()
    
    @app.post("/api/sniffer/start")
    async def sniffer_start():
        if not SCAPY_AVAILABLE:
            return {"success": False, "error": "Scapy not installed"}
        packet_sniffer.start_pcap_capture()
        packet_sniffer.start_sniffing()
        return {"success": True}
    
    @app.post("/api/sniffer/stop")
    async def sniffer_stop():
        packet_sniffer.stop_sniffing()
        return {"success": True}