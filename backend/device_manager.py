"""
NetWatch Advanced Device Manager - ULTIMATE EDITION
- Scans EVERYTHING (all interfaces, all networks)
- Multi-threaded parallel scanning
- Smart detection with timeout optimization
- No skipping - complete network discovery
"""

import time
import socket
import threading
import subprocess
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import re

try:
    from scapy.all import ARP, Ether, srp, srp1, conf as _scapy_conf
    SCAPY_AVAILABLE = True
    # Scapy ships a ~30 000-entry OUI database in conf.manufdb
    _SCAPY_MANUF = getattr(_scapy_conf, 'manufdb', None)
    print("[DeviceManager] Scapy loaded - ARP scan + OUI database available")
except ImportError:
    SCAPY_AVAILABLE = False
    _SCAPY_MANUF = None
    print("[DeviceManager] Scapy not available - using ping+ARP scan")

# Adapter name substrings (case-insensitive) that flag a virtual / host-only NIC.
# Adapters whose names contain any of these are skipped during network discovery so
# that VMware, VirtualBox, Hyper-V and WSL subnets never end up in the scan list.
_VIRTUAL_ADAPTER_KEYWORDS: tuple = (
    'vmware', 'vmnet',
    'virtualbox', 'vboxnet',
    'vethernet',        # Hyper-V virtual switches - covers "vEthernet (WSL)", etc.
    'hyper-v',
    'docker',
    'loopback',         # Npcap loopback adapter
    'teredo', 'isatap', '6to4',
    'bluetooth',
)

# Virtual-machine adapter MAC OUIs (first 3 octets). Catches VirtualBox/VMware/
# Hyper-V host-only adapters even when Windows names them plainly (e.g.
# "Ethernet 2"), so their host-only subnet isn't scanned and the adapter itself
# isn't reported as a "device". OUI-based, so it's generic across machines.
_VIRTUAL_MAC_OUIS: frozenset = frozenset({
    '08:00:27', '0A:00:27',                         # VirtualBox (guest / host-only)
    '00:50:56', '00:0C:29', '00:05:69', '00:1C:14', # VMware
    '00:15:5D',                                     # Hyper-V / WSL
    '00:1C:42',                                     # Parallels
})

# A device must fail to actively reply for this many consecutive scans before
# being marked OFFLINE.  At a 30-second interval, 2 misses ~ 60 seconds.
_OFFLINE_AFTER_MISSED = 2

# Enhanced MAC Vendor Database
MAC_VENDORS = {
    # Major manufacturers
    "00:14:22": "Dell", "00:1A:A0": "HP", "00:1E:4F": "Dell",
    "00:23:12": "Intel", "00:24:7B": "Intel", "00:25:9C": "Intel",
    "00:50:56": "VMware", "08:00:27": "VirtualBox", "00:15:5D": "Hyper-V",
    "00:0C:29": "VMware", "00:50:F2": "Microsoft", "00:1B:63": "Apple",
    "00:26:4D": "Apple", "04:54:53": "Apple", "08:66:98": "Samsung",
    "10:68:3F": "Samsung", "28:6C:07": "Xiaomi", "74:4D:28": "Xiaomi",
    "AC:CF:5C": "OnePlus", "00:11:22": "Realtek", "00:1A:6B": "TP-Link",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "C8:5B:76": "TP-Link", "D8:47:32": "Xiaomi", "E0:D5:5E": "Samsung",
    "70:1C:E7": "TP-Link", "94:57:A5": "Intel", "F4:F5:DB": "Dell",
    "3C:95:09": "Google", "00:00:5E": "IANA", "00:01:42": "Cisco",
    "00:03:93": "Huawei", "00:0F:B0": "ZTE", "00:12:34": "Nokia",
    "00:1C:DF": "Motorola", "00:24:1D": "LG", "00:25:3C": "Sony",
    "00:26:82": "Asus", "00:30:67": "Acer", "00:40:96": "IBM",
    "00:60:08": "NEC", "00:80:77": "Netgear", "00:A0:C9": "Linksys",
    "00:D0:59": "D-Link", "04:7F:0E": "Ubiquiti", "08:10:74": "Cisco",
    "0C:84:DC": "Aruba", "14:CC:20": "Huawei", "18:16:C9": "Samsung",
    "1C:7E:E5": "Intel", "20:AA:4B": "Asus", "24:0A:C4": "Cisco",
    "28:16:A8": "TP-Link", "2C:FD:A1": "Xiaomi", "30:8D:99": "Google",
    "34:96:72": "Netgear", "38:2C:4A": "Intel", "3C:2E:F9": "TP-Link",
    "40:ED:00": "Xiaomi", "44:38:39": "Huawei", "48:5D:36": "Lenovo",
    "4C:32:75": "TP-Link", "50:2B:73": "Xiaomi", "54:10:EC": "Intel",
    "58:00:E3": "Raspberry Pi", "5C:CF:7F": "Apple", "60:45:CB": "Dell",
    "64:BC:0C": "TP-Link", "68:DB:F5": "Apple", "6C:40:8F": "Xiaomi",
    "70:3A:CB": "Intel", "74:DA:38": "TP-Link", "78:4F:43": "Huawei",
    "7C:2A:31": "Apple", "80:2A:A8": "Samsung", "84:38:38": "OnePlus",
    "88:66:5A": "TP-Link", "8C:85:90": "Intel", "90:21:55": "Huawei",
    "94:65:2D": "Xiaomi", "98:3C:89": "Netgear", "9C:FC:E8": "Apple",
    "A0:CC:2B": "TP-Link", "A4:77:33": "Lenovo", "A8:5E:45": "Huawei",
    "AC:9E:17": "Samsung", "B0:FC:36": "Google", "B4:6D:83": "Xiaomi",
    "B8:27:EB": "Raspberry Pi", "BC:46:99": "Intel", "C0:56:E3": "TP-Link",
    "C4:6E:1F": "Huawei", "C8:3A:35": "Apple", "CC:2E:5B": "Asus",
    "D0:17:C2": "Dell", "D4:3B:04": "TP-Link", "D8:5D:E2": "Samsung",
    "DC:4F:22": "OnePlus", "E0:3F:49": "HP", "E4:5F:01": "Intel",
    "E8:6D:52": "TP-Link", "EC:08:6B": "Apple", "F0:76:1C": "Tenda",
    "F4:52:14": "Xiaomi", "F8:59:71": "Google", "FC:AA:14": "Lenovo",
}

@dataclass
class NetworkDevice:
    ip: str
    mac: str
    vendor: str
    hostname: str
    device_type: str
    is_trusted: bool
    is_online: bool
    first_seen: float
    last_seen: float
    response_time: float = 0.0
    missed_scans: int = 0   # consecutive scans with no active reply (ARP or ping)

class DeviceManager:
    # -- scan tuning ---------------------------------------------------------
    # Generous enough that power-saving / idle phones that ignore the first
    # probe still get caught, while staying bounded so a scan finishes in a
    # reasonable time. Nothing here is network-specific.
    ARP_PASSES      = 3       # ARP broadcast sweeps (catch devices waking between passes)
    ARP_TIMEOUT     = 2       # seconds to listen for replies per pass
    ARP_RETRY       = 1       # Scapy re-sends to non-repliers this many times per pass
    ARP_PASS_GAP    = 0.6     # pause between passes so sleeping devices can wake
    PING_TIMEOUT_MS = 700     # per-host ping wait (ms) - long enough for distant/idle hosts
    PING_WORKERS    = 256     # parallel pings (whole /24 effectively at once)
    MAX_SWEEP_HOSTS = 1024    # cap for very large subnets (/16 etc.) to stay fast

    def __init__(self):
        self.devices: Dict[str, NetworkDevice] = {}
        self.trusted_macs: Set[str] = set()
        self.alert_callback = None
        self.scanning = False
        self.scan_thread = None
        # Rich per-subnet targets: each carries the network CIDR AND the local
        # source IP / adapter that owns it, so every sweep goes out the CORRECT
        # adapter (not Scapy's default, which is often a virtual NIC).
        self.scan_targets = self._detect_scan_targets(verbose=True)
        self.networks_to_scan = [t["network"] for t in self.scan_targets]
        print(f"[DeviceManager] Networks to scan: {self.networks_to_scan}")

    def _detect_scan_targets(self, verbose: bool = False) -> List[dict]:
        """Dynamically detect the real LAN subnet(s) from the live adapters.

        Returns a list of dicts: {network, src_ip, iface_name, netmask}. The
        src_ip/iface lets each sweep be sent out the adapter that actually owns
        the subnet. Re-run before every scan, so roaming to a different Wi-Fi /
        hotspot is handled live - nothing is cached from startup or hardcoded.

        How it works
        -------------
        Step 1 - probe which adapter the OS uses to reach the internet by
                 doing a UDP "connect" to 8.8.8.8 (no packets are sent; the
                 OS just consults its routing table and fills in getsockname).
                 This gives us the IP of the correct physical adapter even when
                 multiple NICs are present.

        Step 2 - walk psutil's interface list, skip anything that looks virtual
                 (VMware, VirtualBox, Hyper-V / WSL vEthernet, Docker, ...) by
                 name substring match against _VIRTUAL_ADAPTER_KEYWORDS.

        Step 3 - for each remaining real adapter, compute the network using the
                 adapter's actual IP *and* netmask via Python's ipaddress module,
                 so the CIDR is correct whether the LAN is /24, /22, or /16.
                 The gateway adapter (from step 1) is placed first.

        The result is re-computed every server restart, so switching Wi-Fi
        networks (home -> café -> office) is handled automatically - just restart
        the server and it detects the new subnet with zero code changes.
        """
        import ipaddress as _ipmod

        # -- Step 1: identify the outbound (gateway-facing) IP --------------
        gateway_local_ip: Optional[str] = None
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.settimeout(1)
            probe.connect(("8.8.8.8", 80))
            gateway_local_ip = probe.getsockname()[0]
            probe.close()
            if verbose:
                print(f"[DeviceManager] Gateway-facing adapter IP: {gateway_local_ip}")
        except Exception as exc:
            print(f"[DeviceManager] Gateway probe failed ({exc}); will use all real adapters")

        # -- Step 2: build {ip -> (adapter_name, netmask)} for real adapters -
        ip_to_iface: Dict[str, tuple] = {}
        try:
            import psutil
            iface_stats = psutil.net_if_stats()

            for name, addrs in psutil.net_if_addrs().items():
                stat = iface_stats.get(name)
                if not stat or not stat.isup:
                    continue

                name_lower = name.lower()
                if any(kw in name_lower for kw in _VIRTUAL_ADAPTER_KEYWORDS):
                    if verbose:
                        print(f"[DeviceManager] [SKIP-VIRTUAL] {name}")
                    continue

                # Skip by MAC OUI too — catches VM host-only adapters whose name
                # is generic (e.g. "Ethernet 2") so they aren't scanned/reported.
                adapter_mac = None
                for addr in addrs:
                    if addr.family == psutil.AF_LINK and addr.address:
                        adapter_mac = addr.address.upper().replace('-', ':')
                        break
                if adapter_mac and adapter_mac[:8] in _VIRTUAL_MAC_OUIS:
                    if verbose:
                        print(f"[DeviceManager] [SKIP-VIRTUAL-MAC] {name} ({adapter_mac})")
                    continue

                for addr in addrs:
                    if addr.family != socket.AF_INET:
                        continue
                    ip = addr.address
                    if ip.startswith('127.') or ip.startswith('169.254.'):
                        continue
                    netmask = addr.netmask or '255.255.255.0'
                    ip_to_iface[ip] = (name, netmask)

        except Exception as exc:
            print(f"[DeviceManager] Interface discovery error: {exc}")

        # -- Step 3: order adapters (gateway first), compute real CIDR -------
        # Put the gateway adapter IP first so it is always scanned first.
        ordered = []
        if gateway_local_ip and gateway_local_ip in ip_to_iface:
            ordered.append(gateway_local_ip)
        for ip in ip_to_iface:
            if ip not in ordered:
                ordered.append(ip)

        targets: List[dict] = []
        seen_networks: Set[str] = set()
        for ip in ordered:
            name, netmask = ip_to_iface[ip]
            try:
                net_obj = _ipmod.IPv4Interface(f"{ip}/{netmask}").network
                network = str(net_obj)           # e.g. "192.168.1.0/24"
            except Exception:
                parts   = ip.split('.')
                network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                netmask = '255.255.255.0'

            if network in seen_networks:
                continue
            seen_networks.add(network)
            targets.append({"network": network, "src_ip": ip,
                            "iface_name": name, "netmask": netmask})

            if verbose:
                tag = ("HOME/OFFICE" if ip.startswith('192.168.') else
                       "CORPORATE"   if ip.startswith('10.')       else
                       "PRIVATE"     if ip.startswith('172.')      else "OTHER")
                gw_flag = " <- GATEWAY ADAPTER" if ip == gateway_local_ip else ""
                print(f"[DeviceManager] [REAL-IFACE] {name}: {ip}/{netmask} "
                      f"-> scan {network} [{tag}]{gw_flag}")

        if not targets:
            # Only reached if the machine has no UP real adapter at all
            # (no Wi-Fi, no Ethernet). Re-detected each scan, so reconnecting
            # is picked up automatically without a restart.
            print("[DeviceManager] WARNING: no real adapter found; not connected to a network?")

        return targets
    
    def _get_vendor(self, mac: str) -> str:
        """Resolve MAC OUI to a manufacturer name.

        Priority:
          1. Scapy's bundled manuf database (~30 000 OUI entries) - used when
             Scapy is installed (which it already is for ARP scanning).
          2. The local static table below - covers ~100 common OUIs as a
             fast fallback if the Scapy lookup misses or Scapy is unavailable.
        """
        if not mac or mac == "Unknown" or len(mac) < 6:
            return "Unknown"

        mac_norm = mac.upper().replace('-', ':')

        # --- Priority 1: Scapy manuf database ---
        if _SCAPY_MANUF is not None:
            try:
                result = _SCAPY_MANUF._get_manuf(mac_norm)
                # _get_manuf returns None, the MAC itself, or a vendor string
                if result and result not in (None, mac_norm, mac):
                    return result
            except Exception:
                pass

        # --- Priority 2: local static table ---
        if len(mac_norm) >= 8:
            if mac_norm[:8] in MAC_VENDORS:
                return MAC_VENDORS[mac_norm[:8]]

        clean = mac_norm.replace(':', '')
        if len(clean) >= 6:
            p6 = clean[:6]
            for k, v in MAC_VENDORS.items():
                if k.replace(':', '') == p6:
                    return v

        return "Unknown"
    
    def _get_hostname(self, ip: str) -> str:
        """Get hostname with timeout"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname.split('.')[0] if '.' in hostname else hostname
        except:
            return ip
    
    def _get_device_type(self, vendor: str, ip: str, mac: str) -> str:
        """Determine device type based on multiple factors"""
        # Router/Gateway detection
        if ip.endswith('.1') or ip.endswith('.254'):
            return "🌐 Router/Gateway"
        
        vendor_lower = vendor.lower()
        mac_upper = mac.upper()
        
        # Apple devices
        if 'apple' in vendor_lower or mac_upper.startswith(('00:1B:63', '00:26:4D', '04:54:53', '5C:CF:7F', '68:DB:F5')):
            return "🍎 Apple"
        
        # Mobile devices
        if any(x in vendor_lower for x in ['samsung', 'xiaomi', 'oneplus', 'huawei', 'oppo', 'vivo', 'realme']):
            return "📱 Mobile"
        if mac_upper.startswith(('08:66:98', '10:68:3F', '28:6C:07', '74:4D:28', 'AC:CF:5C', '84:38:38')):
            return "📱 Mobile"
        
        # Computers/Laptops
        if any(x in vendor_lower for x in ['dell', 'hp', 'lenovo', 'asus', 'acer', 'msi', 'gigabyte', 'intel']):
            return "💻 Computer"
        if mac_upper.startswith(('00:14:22', '00:1E:4F', 'F4:F5:DB', 'C8:5B:76')):
            return "💻 Computer"
        
        # Network equipment
        if any(x in vendor_lower for x in ['tp-link', 'netgear', 'd-link', 'linksys', 'cisco', 'tenda', 'mercusys']):
            return "📡 Network Switch/Router"
        if mac_upper.startswith(('00:80:77', '00:A0:C9', '00:D0:59', 'C0:56:E3', 'D4:3B:04')):
            return "📡 Network Device"
        
        # Virtual machines
        if any(x in vendor_lower for x in ['vmware', 'virtualbox', 'hyper-v', 'qemu']):
            return "🖥️ Virtual Machine"
        if mac_upper.startswith(('00:50:56', '08:00:27', '00:15:5D', '00:0C:29')):
            return "🖥️ Virtual Machine"
        
        # Smart devices / IoT
        if any(x in vendor_lower for x in ['google', 'nest', 'amazon', 'echo', 'alexa', 'sony', 'lg', 'philips']):
            return "🎮 Smart Device"
        
        # Raspberry Pi
        if 'raspberry' in vendor_lower or mac_upper.startswith(('B8:27:EB', 'DC:A6:32', '58:00:E3')):
            return "🍓 Raspberry Pi"
        
        return "🔌 Unknown Device"
    
    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_mac(token: str) -> Optional[str]:
        """Return colon-separated uppercase MAC from a token, or None."""
        token = token.strip()
        if re.match(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$', token):
            mac = token.upper().replace('-', ':')
            if mac != 'FF:FF:FF:FF:FF:FF':
                return mac
        return None

    def _get_mac_from_arp(self, ip: str) -> str:
        """Look up a single IP in the OS ARP cache."""
        try:
            r = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2)
            for line in r.stdout.splitlines():
                if ip in line:
                    for token in line.split():
                        mac = self._parse_mac(token)
                        if mac:
                            return mac
        except Exception:
            pass
        return "Unknown"

    def _scapy_iface_for_ip(self, src_ip: str):
        """Return the Scapy interface object whose IPv4 address is src_ip, so we
        send ARP out the adapter that actually OWNS the subnet - not Scapy's
        default (`conf.iface`), which on a multi-adapter machine is often a
        virtual/other NIC and is the usual reason real devices are missed.
        Returns None -> fall back to Scapy's default."""
        if not SCAPY_AVAILABLE or not src_ip:
            return None
        try:
            for iface in _scapy_conf.ifaces.values():
                if getattr(iface, "ip", None) == src_ip:
                    return iface
        except Exception:
            pass
        return None

    def _hosts_for_network(self, network: str, src_ip: Optional[str] = None) -> List[str]:
        """Every usable host IP in the CIDR (e.g. .1-.254 for a /24), derived
        dynamically from the detected subnet - never assumed. Capped at
        MAX_SWEEP_HOSTS so a very large subnet (/16) stays fast; if capped we
        fall back to our own /24 window where local devices actually live."""
        import ipaddress as _ipmod
        try:
            net = _ipmod.ip_network(network, strict=False)
        except Exception:
            base = network.split('/')[0].rsplit('.', 1)[0]
            return [f"{base}.{i}" for i in range(1, 255)]

        if net.num_addresses > self.MAX_SWEEP_HOSTS + 2 and src_ip:
            base = src_ip.rsplit('.', 1)[0]
            print(f"[DeviceManager]   [SWEEP] {network} is large "
                  f"({net.num_addresses} addrs) - sweeping local {base}.0/24 window")
            return [f"{base}.{i}" for i in range(1, 255)]

        return [str(h) for h in net.hosts()]   # .hosts() excludes network+broadcast

    # ------------------------------------------------------------------
    # Phase 1 - multi-pass Scapy ARP scan (out the CORRECT adapter)
    # ------------------------------------------------------------------

    def _arp_scan_multipass(self, network: str, src_ip: str,
                            hosts: List[str]) -> Dict[str, str]:
        """
        Broadcast ARP requests across the whole subnet, ARP_PASSES times, out the
        adapter that owns src_ip. Generous timeout/retry so power-saving phones
        that ignore the first probe still answer a later pass. Returns {ip: mac}.
        """
        found: Dict[str, str] = {}

        if not SCAPY_AVAILABLE:
            print("[DeviceManager]   [ARP-SCAN] Scapy not available - skipping ARP passes")
            return found

        iface = self._scapy_iface_for_ip(src_ip)
        iface_label = (getattr(iface, "name", None) or getattr(iface, "description", None)
                       or "scapy-default")

        # Sweep the whole /24 (or smaller) via the CIDR; for a capped large
        # subnet, hand Scapy the explicit host list instead.
        import ipaddress as _ipmod
        try:
            net = _ipmod.ip_network(network, strict=False)
            pdst = network if net.num_addresses <= len(hosts) + 2 else hosts
        except Exception:
            pdst = hosts

        passes = self.ARP_PASSES
        for pass_num in range(1, passes + 1):
            print(f"[DeviceManager]   [ARP-SCAN] Pass {pass_num}/{passes} on {network} "
                  f"via {iface_label} (timeout={self.ARP_TIMEOUT}s, retry={self.ARP_RETRY}) ...")
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst)
                kw = dict(timeout=self.ARP_TIMEOUT, verbose=0, inter=0, retry=self.ARP_RETRY)
                if iface is not None:
                    kw["iface"] = iface
                answered, _ = srp(pkt, **kw)

                new_this_pass = 0
                for _, rcv in answered:
                    ip  = rcv.psrc
                    mac = rcv.hwsrc.upper().replace('-', ':')
                    if ip not in found:
                        found[ip] = mac
                        print(f"[DeviceManager]   [ARP-SCAN] Pass {pass_num}: NEW  {ip:<18} -> {mac}")
                        new_this_pass += 1
                    elif found[ip] == "Unknown" and mac != "Unknown":
                        found[ip] = mac

                print(f"[DeviceManager]   [ARP-SCAN] Pass {pass_num}: {new_this_pass} new, "
                      f"{len(found)} total so far")

            except PermissionError:
                print("[DeviceManager]   [ARP-SCAN] PermissionError - run as Administrator with Npcap")
                break
            except Exception as exc:
                low = str(exc).lower()
                if any(k in low for k in ('npcap', 'winpcap', 'wpcap', 'socket')):
                    print("[DeviceManager]   [ARP-SCAN] Npcap missing - install from https://npcap.com")
                else:
                    print(f"[DeviceManager]   [ARP-SCAN] Error: {exc}")
                break

            if pass_num < passes:
                time.sleep(self.ARP_PASS_GAP)   # gap so sleeping devices can wake

        print(f"[DeviceManager]   [ARP-SCAN] Done - {len(found)} device(s) replied to ARP "
              f"after {passes} pass(es)")
        return found

    # ------------------------------------------------------------------
    # Phase 2 - parallel ping sweep -> OS ARP cache lookup
    # ------------------------------------------------------------------

    def _ping_sweep(self, hosts: List[str]) -> Set[str]:
        """
        Ping every host in `hosts` in parallel. This does double duty: it finds
        ICMP-alive hosts AND makes the OS resolve each one, populating the ARP
        cache that later phases harvest - so even devices that drop our Scapy
        broadcast (but answer ping) get a MAC. Returns the set of responders.

        Only count a reply that actually contains 'TTL=' - a "Destination host
        unreachable" message also exits 0 on Windows but is NOT a live host.
        Note: some phones drop ICMP entirely; that's why ARP + cache run too.
        """
        responded: Set[str] = set()
        lock = threading.Lock()

        print(f"[DeviceManager]   [PING] Pinging {len(hosts)} host(s) "
              f"({self.PING_TIMEOUT_MS} ms each, {self.PING_WORKERS} workers) ...")

        def _ping(ip: str) -> None:
            try:
                r = subprocess.run(
                    ["ping", "-n", "1", "-w", str(self.PING_TIMEOUT_MS), ip],
                    capture_output=True,
                    creationflags=0x08000000,   # CREATE_NO_WINDOW (Windows constant)
                )
                if r.returncode == 0 and b"TTL=" in (r.stdout or b"").upper():
                    with lock:
                        responded.add(ip)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.PING_WORKERS) as ex:
            futs = [ex.submit(_ping, ip) for ip in hosts]
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception:
                    pass

        print(f"[DeviceManager]   [PING] {len(responded)} host(s) replied to ping")
        return responded

    # ------------------------------------------------------------------
    # Phase 3 - full OS ARP table dump
    # ------------------------------------------------------------------

    def _read_full_arp_cache(self, network: str) -> Dict[str, str]:
        """
        Run 'arp -a' once and harvest ALL dynamic entries that belong to this
        subnet (membership tested via ipaddress, so it's correct for any prefix
        - /24, /22, /16 ...). Catches devices whose entries exist from any prior
        communication (DHCP, mDNS, the ping sweep above) even if they never
        answered our broadcast. Returns {ip: mac}.
        """
        import ipaddress as _ipmod
        try:
            net = _ipmod.ip_network(network, strict=False)
        except Exception:
            net = None
        found: Dict[str, str] = {}

        print(f"[DeviceManager]   [ARP-CACHE] Dumping OS ARP table for {network} ...")

        try:
            r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip = parts[0].strip()
                try:
                    addr = _ipmod.ip_address(ip)
                except ValueError:
                    continue
                if net is not None and addr not in net:
                    continue
                last_octet = ip.rsplit('.', 1)[-1]
                if last_octet in ('0', '255') or ip.startswith(('224.', '239.')):
                    continue
                for token in parts[1:]:
                    mac = self._parse_mac(token)
                    if mac:
                        found[ip] = mac
                        print(f"[DeviceManager]   [ARP-CACHE] {ip:<18} -> {mac}")
                        break
        except Exception as exc:
            print(f"[DeviceManager]   [ARP-CACHE] Error: {exc}")

        print(f"[DeviceManager]   [ARP-CACHE] {len(found)} entr"
              f"{'y' if len(found) == 1 else 'ies'} for this subnet in OS table")
        return found

    # ------------------------------------------------------------------
    # Combined 3-phase scan for one subnet
    # ------------------------------------------------------------------

    def _scan_network_comprehensive(self, target: dict) -> Tuple[List[Dict], Set[str]]:
        """
        Sweep ONE subnet with three methods and merge - a device counts as found
        if ANY method sees it:
          Phase 1 - parallel ping sweep of every host (wakes idle devices AND
                    populates the OS ARP cache for the later phases).
          Phase 2 - multi-pass Scapy ARP broadcast out the correct adapter.
          Phase 3 - full 'arp -a' OS cache dump.

        Returns (all_devices, active_ips). active_ips = replied to ARP or ping
        this round; ARP-cache-only entries are discovery-only (may be stale).
        """
        network  = target["network"]
        src_ip   = target.get("src_ip")
        iface_nm = target.get("iface_name")

        # Full host range for the detected CIDR - every host, derived dynamically.
        hosts = self._hosts_for_network(network, src_ip)
        total_probed = len(hosts)

        print(f"\n[DeviceManager] {'='*60}")
        print(f"[DeviceManager] SCANNING SUBNET : {network}")
        print(f"[DeviceManager] via adapter     : {iface_nm}  (src {src_ip})")
        print(f"[DeviceManager] hosts to probe  : {total_probed}  "
              f"({hosts[0]} ... {hosts[-1]})" if hosts else "(none)")
        print(f"[DeviceManager] {'='*60}")

        merged: Dict[str, str] = {}   # ip -> best-known mac
        def _merge(source: Dict[str, str]) -> int:
            added = 0
            for ip, mac in source.items():
                if ip not in merged:
                    merged[ip] = mac
                    added += 1
                elif merged[ip] == "Unknown" and mac != "Unknown":
                    merged[ip] = mac   # upgrade to real MAC
            return added

        # -- Phase 1 - ping sweep FIRST (wakes devices + fills the ARP cache) --
        ping_found = self._ping_sweep(hosts)

        # -- Phase 2 - multi-pass ARP broadcast out the correct adapter --
        arp_found = self._arp_scan_multipass(network, src_ip, hosts)
        _merge(arp_found)

        # Resolve a MAC for each ping responder from the (now warm) cache, merge.
        ping_macs = {ip: self._get_mac_from_arp(ip) for ip in ping_found}
        _merge(ping_macs)

        # -- Phase 3 - full OS ARP cache dump (discovery only) --
        cache_found = self._read_full_arp_cache(network)
        _merge(cache_found)

        # Active = actually replied this round (ARP reply or ping). Cache-only
        # entries are NOT active (they may be stale).
        active_ips: Set[str] = set(arp_found.keys()) | set(ping_found)

        # -- per-scan COVERAGE summary (so coverage is verifiable on any net) --
        print(f"\n[DeviceManager] ---- COVERAGE for {network} ----")
        print(f"[DeviceManager]   IPs probed       : {total_probed}")
        print(f"[DeviceManager]   replied via ARP  : {len(arp_found)}")
        print(f"[DeviceManager]   replied via ping : {len(ping_found)}")
        print(f"[DeviceManager]   in OS ARP cache  : {len(cache_found)}")
        print(f"[DeviceManager]   TOTAL discovered : {len(merged)}  "
              f"(active {len(active_ips)}, cache-only {len(merged) - len(active_ips)})")

        # -- AP/Client Isolation heuristic --
        # On a populated /24, near-zero ARP replies across a full sweep is the
        # classic signature of layer-2 client isolation (a ROUTER/HOTSPOT setting
        # that blocks client-to-client ARP) - not a scan bug. Flag it clearly.
        arp_non_self   = [ip for ip in arp_found if ip != src_ip]
        seen_not_arp   = (set(merged) - set(arp_found)) - ({src_ip} if src_ip else set())
        if total_probed >= 16 and len(arp_non_self) <= 1:
            print(f"[DeviceManager]   [WARN] POSSIBLE AP/CLIENT ISOLATION: only "
                  f"{len(arp_non_self)} other device(s) answered ARP across "
                  f"{total_probed} hosts.")
            print(f"[DeviceManager]     This is the signature of 'AP Isolation' / "
                  f"'Client Isolation' on the router/hotspot (it blocks")
            print(f"[DeviceManager]     client-to-client ARP) - a ROUTER SETTING, not a code bug. "
                  f"Phone hotspots usually isolate clients by design.")
            print(f"[DeviceManager]     Fix: disable AP/Client Isolation on the router, "
                  f"or test on a normal home/office Wi-Fi.")
            if seen_not_arp:
                print(f"[DeviceManager]     (ping/cache still saw: {sorted(seen_not_arp)})")

        # -- detailed device table --
        print(f"[DeviceManager]   {'IP':<16} {'MAC':<19} {'SOURCE':<7} {'VENDOR'}")
        for ip in sorted(merged, key=lambda x: [int(p) for p in x.split('.')]):
            mac    = merged[ip]
            vendor = self._get_vendor(mac)
            src    = "active" if ip in active_ips else "cache"
            print(f"[DeviceManager]   {ip:<16} {mac:<19} {src:<7} {vendor}")
        print(f"[DeviceManager] {'='*60}\n")

        return [{"ip": ip, "mac": mac} for ip, mac in merged.items()], active_ips

    # ------------------------------------------------------------------
    # Public scan entry point
    # ------------------------------------------------------------------

    def scan_all_networks(self) -> Tuple[List[Dict], Set[str]]:
        """Run the comprehensive scan across every detected subnet.

        Targets are RE-DETECTED here on every scan, so roaming to a different
        Wi-Fi / hotspot is picked up live (no restart). Returns (all_devices,
        active_ips), active_ips = union of IPs that replied (ARP or ping).
        """
        # Re-detect current adapters/subnets (quietly) so we always sweep the
        # network we're on RIGHT NOW - nothing cached from startup.
        prev = set(self.networks_to_scan)
        self.scan_targets    = self._detect_scan_targets(verbose=False)
        self.networks_to_scan = [t["network"] for t in self.scan_targets]
        if set(self.networks_to_scan) != prev:
            print(f"[DeviceManager] Network change detected -> now scanning: "
                  f"{self.networks_to_scan}")

        all_devices: List[Dict] = []
        all_active_ips: Set[str] = set()
        total_start = time.time()

        if not self.scan_targets:
            print("[DeviceManager] No active network adapter - nothing to scan "
                  "(connect to Wi-Fi/hotspot).")
            return all_devices, all_active_ips

        print(f"[DeviceManager] Starting comprehensive scan of "
              f"{len(self.scan_targets)} subnet(s): {self.networks_to_scan}")

        for idx, target in enumerate(self.scan_targets, 1):
            print(f"\n[DeviceManager] Subnet {idx}/{len(self.scan_targets)}: {target['network']}")
            devices, active_ips = self._scan_network_comprehensive(target)
            all_devices.extend(devices)
            all_active_ips.update(active_ips)

        elapsed = time.time() - total_start
        print(f"\n[DeviceManager] [OK] All scans complete - "
              f"{len(all_devices)} total device(s), {len(all_active_ips)} actively replied, "
              f"in {elapsed:.1f}s")
        return all_devices, all_active_ips
    
    def update_devices(self, discovered: List[Dict], active_ips: Set[str]) -> List[NetworkDevice]:
        """Merge scan results into the device database.

        Online/offline rules:
          - ONLINE  : ip is in active_ips (replied to ARP broadcast or ping this round)
          - OFFLINE : ip has NOT actively replied for _OFFLINE_AFTER_MISSED consecutive scans
          - ARP-cache-only entries (in discovered but NOT in active_ips) increment
            missed_scans and flip offline once the threshold is reached.
        """
        new_devices = []
        current_ips = set()
        now = time.time()

        for device in discovered:
            ip  = device["ip"]
            mac = device.get("mac", "Unknown")
            current_ips.add(ip)
            is_active = ip in active_ips   # actually replied this round

            if ip in self.devices:
                dev = self.devices[ip]
                if is_active:
                    dev.last_seen   = now
                    dev.is_online   = True
                    dev.missed_scans = 0
                else:
                    # Only in stale ARP cache - treat as a potential miss
                    dev.missed_scans += 1
                    if dev.missed_scans >= _OFFLINE_AFTER_MISSED and dev.is_online:
                        dev.is_online = False
                        print(f"[DeviceManager] {ip} - no active reply for "
                              f"{dev.missed_scans} scan(s) -> OFFLINE")
                # Always upgrade Unknown MAC if we now have a real one
                if dev.mac == "Unknown" and mac != "Unknown":
                    dev.mac    = mac
                    dev.vendor = self._get_vendor(mac)
                continue

            # Brand-new device
            vendor      = self._get_vendor(mac)
            device_type = self._get_device_type(vendor, ip, mac)
            is_trusted  = mac in self.trusted_macs
            hostname    = self._get_hostname(ip)

            new_device = NetworkDevice(
                ip=ip, mac=mac, vendor=vendor, hostname=hostname,
                device_type=device_type, is_trusted=is_trusted,
                is_online=is_active,
                first_seen=now, last_seen=now if is_active else 0,
                response_time=0,
                missed_scans=0 if is_active else 1
            )
            self.devices[ip] = new_device
            new_devices.append(new_device)

            if self.alert_callback and is_active:
                self.alert_callback(
                    title="New Device Detected",
                    message=f"{ip} ({vendor} - {device_type}) joined the network",
                    severity="info",
                    value=0
                )
            status_tag = "ACTIVE" if is_active else "cache-only"
            print(f"[DeviceManager] New device: {ip} | MAC: {mac} | Vendor: {vendor} | {status_tag}")

        # Devices absent from ALL three scan phases - definite misses
        # Guard: only process if the scan returned at least some results
        # (an empty result from a totally failed scan must not wipe the table)
        if current_ips:
            for ip in list(self.devices.keys()):
                if ip not in current_ips:
                    dev = self.devices[ip]
                    dev.missed_scans += 1
                    if dev.missed_scans >= _OFFLINE_AFTER_MISSED and dev.is_online:
                        dev.is_online = False
                        print(f"[DeviceManager] {ip} - not seen for "
                              f"{dev.missed_scans} scan(s) -> OFFLINE")

        return new_devices
    
    def start_scanning(self, interval: int = 30, alert_callback=None):
        """Start continuous scanning"""
        self.alert_callback = alert_callback
        self.scanning = True
        
        def scan_loop():
            scan_count = 0
            print(f"[DeviceManager] [SCAN] Continuous scanning started - interval: {interval}s")
            while self.scanning:
                scan_count += 1
                print(f"\n[DeviceManager] >> SCAN #{scan_count} starting...")
                try:
                    devices, active_ips = self.scan_all_networks()
                    new = self.update_devices(devices, active_ips)
                    if new:
                        print(f"[DeviceManager] [NEW] {len(new)} new device(s) discovered in this scan")
                    print(f"[DeviceManager] [STATS] Total tracked devices: {len(self.devices)}")
                except Exception as e:
                    print(f"[DeviceManager] Scan error: {e}")
                time.sleep(interval)
        
        self.scan_thread = threading.Thread(target=scan_loop, daemon=True)
        self.scan_thread.start()
        print("[DeviceManager] [OK] Scanner thread active")
    
    def stop_scanning(self):
        self.scanning = False
        print("[DeviceManager] Scanner stopped")
    
    def add_trusted_device(self, mac: str, name: str):
        self.trusted_macs.add(mac.upper())
        for device in self.devices.values():
            if device.mac == mac.upper():
                device.is_trusted = True
    
    def get_stats(self) -> dict:
        total = len(self.devices)
        online = sum(1 for d in self.devices.values() if d.is_online)
        trusted = sum(1 for d in self.devices.values() if d.is_trusted)
        
        # Count by device type
        device_types = {}
        for device in self.devices.values():
            dtype = device.device_type
            device_types[dtype] = device_types.get(dtype, 0) + 1
        
        return {
            "scanning": self.scanning,
            "networks_scanning": self.networks_to_scan,
            "total_networks": len(self.networks_to_scan),
            "total_devices": total,
            "online_devices": online,
            "trusted_devices": trusted,
            "unknown_devices": total - trusted,
            "device_types": device_types,
            "scapy_available": SCAPY_AVAILABLE
        }
    
    def get_device_list(self) -> List[dict]:
        return [{
            "ip": d.ip, "mac": d.mac, "vendor": d.vendor,
            "hostname": d.hostname, "type": d.device_type,
            "trusted": d.is_trusted, "online": d.is_online,
            "first_seen": d.first_seen, "last_seen": d.last_seen
        } for d in self.devices.values()]

# Singleton instance
device_manager = DeviceManager()