# backend/advanced_packet_stream.py

"""
Advanced Packet Stream - World's Most Advanced Packet Analysis
Features: Real-time packets, PCAP download, Wireshark export, Packet search, Protocol filtering
"""

import asyncio
import time
import json
import base64
from collections import deque
from datetime import datetime
from typing import List, Dict, Optional
import hashlib
import struct

class AdvancedPacketStream:
    def __init__(self):
        self.packets = deque(maxlen=1000)  # Store last 1000 packets
        self.subscribers = []
        self._loop = None  # Set by main.py after the event loop starts
        self.filters = {
            'protocols': [],  # tcp, udp, icmp, etc.
            'src_ips': [],
            'dst_ips': [],
            'min_size': 0,
            'max_size': 65535
        }
        self.packet_stats = {
            'total': 0,
            'by_protocol': {},
            'by_size': {},
            'top_src_ips': {},
            'top_dst_ips': {}
        }
        self.pcap_buffer = deque(maxlen=10000)  # Store raw packets for PCAP

    def set_loop(self, loop):
        """Store the main asyncio event loop so add_packet() can schedule sends from threads."""
        self._loop = loop

    def _update_stats(self, packet):
        """Update packet statistics"""
        self.packet_stats['total'] += 1
        
        # Protocol stats
        proto = packet.get('protocol', 'unknown')
        self.packet_stats['by_protocol'][proto] = self.packet_stats['by_protocol'].get(proto, 0) + 1
        
        # Size stats
        size = packet.get('size', 0)
        size_range = f"{size//100*100}-{(size//100+1)*100}" if size < 1000 else "1000+"
        self.packet_stats['by_size'][size_range] = self.packet_stats['by_size'].get(size_range, 0) + 1
        
        # Top IPs
        src = packet.get('src_ip', '')
        if src and not src.startswith(('192.168.', '10.', '127.', '172.')):
            self.packet_stats['top_src_ips'][src] = self.packet_stats['top_src_ips'].get(src, 0) + 1
        
        dst = packet.get('dst_ip', '')
        if dst and not dst.startswith(('192.168.', '10.', '127.', '172.')):
            self.packet_stats['top_dst_ips'][dst] = self.packet_stats['top_dst_ips'].get(dst, 0) + 1
        
        # Keep only top 20
        self.packet_stats['top_src_ips'] = dict(sorted(self.packet_stats['top_src_ips'].items(), key=lambda x: x[1], reverse=True)[:20])
        self.packet_stats['top_dst_ips'] = dict(sorted(self.packet_stats['top_dst_ips'].items(), key=lambda x: x[1], reverse=True)[:20])
    
    def _should_filter(self, packet):
        """Check if packet matches filters"""
        if self.filters['protocols']:
            if packet.get('protocol', '').lower() not in self.filters['protocols']:
                return True
        
        if self.filters['src_ips']:
            if packet.get('src_ip', '') not in self.filters['src_ips']:
                return True
        
        if self.filters['dst_ips']:
            if packet.get('dst_ip', '') not in self.filters['dst_ips']:
                return True
        
        size = packet.get('size', 0)
        if size < self.filters['min_size'] or (self.filters['max_size'] and size > self.filters['max_size']):
            return True
        
        return False
    
    def add_packet(self, packet_info: Dict):
        """Add a captured packet to stream"""
        packet = {
            'id': hashlib.md5(f"{packet_info.get('timestamp', time.time())}{packet_info.get('src_ip', '')}{packet_info.get('dst_ip', '')}".encode()).hexdigest()[:8],
            'timestamp': packet_info.get('timestamp', time.time()),
            'time_str': datetime.fromtimestamp(packet_info.get('timestamp', time.time())).strftime('%H:%M:%S.%f')[:-3],
            'src_ip': packet_info.get('src_ip', ''),
            'dst_ip': packet_info.get('dst_ip', ''),
            'src_port': packet_info.get('src_port', 0),
            'dst_port': packet_info.get('dst_port', 0),
            'protocol': packet_info.get('protocol', 'unknown').upper(),
            'size': packet_info.get('size', 0),
            'ttl': packet_info.get('ttl', 0),
            'flags': packet_info.get('flags', ''),
            'info': packet_info.get('info', ''),
            'raw_hex': packet_info.get('raw_hex', '')
        }
        
        # Update stats
        self._update_stats(packet)
        
        # Check filters
        if self._should_filter(packet):
            return
        
        self.packets.appendleft(packet)

        # Broadcast to subscribers.
        # add_packet() is called from Scapy's background thread, not from the asyncio
        # event loop thread, so asyncio.create_task() would raise RuntimeError here.
        # run_coroutine_threadsafe() is the correct cross-thread scheduler.
        if self._loop and self._loop.is_running():
            for ws in self.subscribers:
                asyncio.run_coroutine_threadsafe(
                    self._send_to_subscriber(ws, packet), self._loop
                )
    
    def buffer_raw(self, timestamp: float, raw_bytes: bytes):
        """Buffer the real raw frame bytes of a captured packet for PCAP export.

        Called from the sniffer thread alongside add_packet(). We store the
        actual on-the-wire bytes (full Ethernet frame) plus the capture
        timestamp so export_pcap() can produce a Wireshark-valid file.
        """
        if raw_bytes:
            self.pcap_buffer.append((timestamp, bytes(raw_bytes)))

    async def _send_to_subscriber(self, ws, packet):
        try:
            await ws.send_text(json.dumps({
                'type': 'packet',
                'data': packet
            }))
        except:
            pass
    
    async def subscribe(self, websocket):
        """Subscribe client to packet stream"""
        self.subscribers.append(websocket)
        # Send last 50 packets
        for packet in list(self.packets)[:50]:
            await websocket.send_text(json.dumps({
                'type': 'packet',
                'data': packet
            }))
        # Send current stats
        await websocket.send_text(json.dumps({
            'type': 'stats',
            'data': self.get_stats()
        }))
    
    def unsubscribe(self, websocket):
        if websocket in self.subscribers:
            self.subscribers.remove(websocket)
    
    def set_filter(self, filter_type: str, values: List):
        """Set packet filters"""
        if filter_type == 'protocol':
            self.filters['protocols'] = [v.lower() for v in values]
        elif filter_type == 'src_ip':
            self.filters['src_ips'] = values
        elif filter_type == 'dst_ip':
            self.filters['dst_ips'] = values
        elif filter_type == 'size':
            self.filters['min_size'] = values[0] if values else 0
            self.filters['max_size'] = values[1] if len(values) > 1 else 65535
        elif filter_type == 'clear':
            self.filters = {
                'protocols': [],
                'src_ips': [],
                'dst_ips': [],
                'min_size': 0,
                'max_size': 65535
            }
    
    def get_stats(self) -> Dict:
        """Get packet statistics"""
        return {
            'total_packets': self.packet_stats['total'],
            'by_protocol': self.packet_stats['by_protocol'],
            'by_size': self.packet_stats['by_size'],
            'top_src_ips': self.packet_stats['top_src_ips'],
            'top_dst_ips': self.packet_stats['top_dst_ips'],
            'active_subscribers': len(self.subscribers),
            'buffer_size': len(self.packets)
        }
    
    def get_packets(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get paginated packets"""
        packets_list = list(self.packets)
        return packets_list[offset:offset+limit]
    
    def export_pcap(self) -> bytes:
        """Export the buffered raw frames as a valid PCAP that opens in Wireshark.

        Uses Scapy's RawPcapWriter to write the ACTUAL captured bytes (full
        Ethernet frames) with their real capture timestamps. linktype=1 is
        Ethernet, matching what the sniffer captures via Npcap.

        Falls back to a valid empty PCAP (just the global header) if Scapy is
        unavailable or nothing has been captured yet.
        """
        frames = list(self.pcap_buffer)   # list of (timestamp, raw_bytes)

        # Valid empty-PCAP global header (Ethernet, microsecond resolution)
        empty_header = struct.pack('IHHIIII',
            0xa1b2c3d4,  # magic number
            2, 4,        # version major/minor
            0, 0,        # thiszone, sigfigs
            65535,       # snaplen
            1            # network = LINKTYPE_ETHERNET
        )

        if not frames:
            return empty_header

        try:
            import io
            from scapy.utils import RawPcapWriter

            buf = io.BytesIO()
            # RawPcapWriter writes raw bytes directly without re-parsing layers,
            # so even unusual/truncated frames are written faithfully.
            writer = RawPcapWriter(buf, linktype=1, sync=False)
            # Touch the stream so the global header is emitted even before first packet.
            writer._write_header(None)
            for ts, raw in frames:
                try:
                    writer.write_packet(raw, sec=int(ts), usec=int((ts - int(ts)) * 1_000_000))
                except Exception:
                    # Older Scapy signature: write() infers time
                    try:
                        writer.write(raw)
                    except Exception:
                        pass
            writer.flush()
            data = buf.getvalue()
            buf.close()
            return data if data else empty_header
        except Exception as exc:
            print(f"[PacketStream] PCAP export error ({exc}); returning empty PCAP")
            return empty_header
    
    def clear_stats(self):
        """Clear all statistics"""
        self.packet_stats = {
            'total': 0,
            'by_protocol': {},
            'by_size': {},
            'top_src_ips': {},
            'top_dst_ips': {}
        }
        self.packets.clear()
        self.pcap_buffer.clear()

# Singleton instance
packet_stream = AdvancedPacketStream()