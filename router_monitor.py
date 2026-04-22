import hashlib
import time
import json
import sys
import os
import re as re_module
import subprocess
import socket
import threading
import platform
from concurrent.futures import ThreadPoolExecutor
import requests
from datetime import datetime
import net_blocker
import ai_handler
from env_config import load_env_local

load_env_local()

# Fix Windows console encoding for emojis
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ── Configuration ────────────────────────────────────────
ROUTER         = os.getenv("ROUTER_URL", "http://192.168.0.1")
USERNAME       = os.getenv("ROUTER_USERNAME", "admin")
PASSWORD       = os.getenv("ROUTER_PASSWORD", "")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID        = os.getenv("TELEGRAM_CHAT_ID", "")
INTERVAL       = int(os.getenv("MONITOR_INTERVAL", "30"))
TRUSTED_FILE   = os.getenv("TRUSTED_FILE", "trusted_devices.json")
GATEWAY        = os.getenv("GATEWAY_IP", "192.168.0.1")
NETWORK_SUBNET = os.getenv("NETWORK_SUBNET", "192.168.0")
DEVICE_NAME_FILE = os.getenv("DEVICE_NAME_FILE", "device_names.json")

# ── OpenRouter AI Config (optional, for natural language) ─
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free")

session = requests.Session()


def _is_wsl():
    """Return True when running inside Windows Subsystem for Linux."""
    return "microsoft" in platform.release().lower() or bool(os.getenv("WSL_INTEROP"))


def _win_cmd(name):
    """Use .exe command names from WSL, plain names on Windows."""
    return f"{name}.exe" if _is_wsl() else name


def _get_windows_arp_output():
    """Fetch Windows ARP table with retry/fallback to avoid transient timeouts."""
    last_err = None

    for timeout_secs in (10, 20):
        try:
            result = subprocess.run(
                [_win_cmd("arp"), "-a"],
                capture_output=True,
                text=True,
                timeout=timeout_secs
            )
            if result.stdout:
                return result.stdout
        except Exception as e:
            last_err = e

    # In WSL, cmd.exe sometimes executes Windows CLI more reliably.
    if _is_wsl():
        try:
            result = subprocess.run(
                ["cmd.exe", "/C", "arp -a"],
                capture_output=True,
                text=True,
                timeout=20
            )
            if result.stdout:
                return result.stdout
        except Exception as e:
            last_err = e

    raise RuntimeError(last_err) if last_err else RuntimeError("Unable to read ARP table")

# ── Authentication for ZLT X20 ───────────────────────────
def login():
    """Login to ZLT X20 router"""
    
    # First, get initial session cookie
    print("🌐 Getting initial session...")
    try:
        resp = session.get(f"{ROUTER}/")
        print(f"   Initial session cookie: {session.cookies.get('sessionId', 'none')}")
    except:
        pass
    
    # Try different password hash methods
    password_hashes = {
        "plain": PASSWORD,
        "md5": hashlib.md5(PASSWORD.encode()).hexdigest(),
        "sha256": hashlib.sha256(PASSWORD.encode()).hexdigest(),
    }
    
    for hash_type, pwd_hash in password_hashes.items():
        print(f"\n🔐 Trying {hash_type} password hash...")
        
        login_data = {
            "cmd": 100,  # Login command
            "method": "POST",
            "username": USERNAME,
            "password": pwd_hash,
            "isAutoUpgrade": "1",
            "sessionId": ""  # Empty for login
        }
        
        try:
            resp = session.post(
                f"{ROUTER}/cgi-bin/http.cgi",
                json=login_data,
                timeout=5
            )
            
            if resp.status_code == 200:
                try:
                    result = resp.json()
                    print(f"   Response: {result}")
                    
                    # Check if login successful
                    if result.get("success") == True:
                        session_id = result.get("sessionId", "")
                        if session_id and session_id != "null":
                            print(f"   ✅ Login successful with {hash_type} hash!")
                            print(f"   Session ID: {session_id}")
                            return session_id
                    elif "sessionId" in result:
                        session_id = result.get("sessionId")
                        if session_id and session_id != "null":
                            print(f"   ✅ Got session ID: {session_id}")
                            return session_id
                    else:
                        print(f"   ❌ Login failed: {result.get('message', 'Unknown error')}")
                        
                except json.JSONDecodeError:
                    print(f"   Response not JSON: {resp.text[:100]}")
                    
        except Exception as e:
            print(f"   Error: {e}")
    
    print("\n❌ All login attempts failed")
    return ""

# ── Get Connected Devices ────────────────────────────────
def get_devices(session_id):
    """Fetch connected devices from router"""
    if not session_id:
        print("   No session ID available")
        return {}
    
    print(f"\n📡 Fetching device list with session: {session_id}")
    
    # Try different commands that might return device list
    device_commands = [401, 402, 403, 404, 405, 410, 420, 430, 440, 450]
    
    for cmd in device_commands:
        try:
            device_data = {
                "cmd": cmd,
                "method": "GET",
                "sessionId": session_id
            }
            
            resp = session.post(
                f"{ROUTER}/cgi-bin/http.cgi",
                json=device_data,
                timeout=5
            )
            
            if resp.status_code == 200:
                try:
                    result = resp.json()
                    
                    # Check if we got device data
                    if result.get("success") == True:
                        # Look for device list in response
                        devices = {}
                        
                        # Common keys where device list might be stored
                        possible_keys = [
                            "dhcp_list_info", "device_list", "hosts", 
                            "clients", "stations", "data", "list"
                        ]
                        
                        for key in possible_keys:
                            if key in result:
                                device_list = result[key]
                                if isinstance(device_list, list):
                                    for device in device_list:
                                        mac = device.get("mac", "").upper().strip()
                                        if mac:
                                            devices[mac] = {
                                                "ip": device.get("ip", device.get("IP", "?")),
                                                "hostname": device.get("hostname", device.get("name", "Unknown")),
                                                "iface": device.get("interface", device.get("type", "WiFi"))
                                            }
                                    if devices:
                                        print(f"   ✅ Found {len(devices)} devices using cmd={cmd}")
                                        return devices
                        
                        # If no device list found but response has data
                        if not devices and len(result) > 2:
                            print(f"   cmd={cmd} returned: {list(result.keys())}")
                            
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            print(f"   Error with cmd={cmd}: {e}")
    
    return {}

# ── Network Scanner (replaces hardcoded fallback) ────────
def ping_host(ip):
    """Ping a single host to populate neighbor table."""
    try:
        if platform.system().lower().startswith("win") or _is_wsl():
            cmd = [_win_cmd("ping"), "-n", "1", "-w", "500", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except:
        pass


def _ping_sweep_subnet(subnet, max_workers=32):
    """Populate neighbor cache with bounded parallel pings."""
    ips = [f"{subnet}.{i}" for i in range(2, 255)]
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(ping_host, ips))

def _scan_network_windows(subnet):
    """Windows scanner using arp/getmac/ipconfig."""
    try:
        arp_output = _get_windows_arp_output()
    except Exception as e:
        print(f"   ⚠️ ARP read failed: {e}; warming cache and retrying once...")
        _ping_sweep_subnet(subnet, max_workers=16 if _is_wsl() else 32)
        try:
            arp_output = _get_windows_arp_output()
        except Exception as e2:
            print(f"   ❌ ARP scan failed: {e2}")
            return {}

    devices = {}
    arp_pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+(\w+)'

    for match in re_module.finditer(arp_pattern, arp_output):
        ip = match.group(1)
        mac = match.group(2).upper().replace("-", ":")
        entry_type = match.group(3)

        if entry_type.lower() not in ("dynamic", "static"):
            continue
        if not ip.startswith(f"{subnet}."):
            continue

        last_octet = int(ip.split(".")[-1])
        if last_octet in (0, 1, 255):
            continue

        if mac.startswith("FF:FF") or mac.startswith("01:00") or mac.startswith("33:33"):
            continue

        hostname = f"Device-{last_octet}"
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            pass

        devices[mac] = {
            "ip": ip,
            "hostname": hostname,
            "iface": "WiFi"
        }

    try:
        iface_pattern = r'Interface:\s+(' + subnet.replace('.', r'\.') + r'\.\d+)'
        iface_match = re_module.search(iface_pattern, arp_output)
        if iface_match:
            local_ip = iface_match.group(1)
            local_mac = None

            try:
                mac_result = subprocess.run(
                    [_win_cmd("getmac"), "/fo", "csv", "/nh", "/v"],
                    capture_output=True, text=True, timeout=5
                )
                for line in mac_result.stdout.strip().split("\n"):
                    line = line.strip()
                    if not line or "disconnected" in line.lower():
                        continue
                    parts = line.split(",")
                    if len(parts) >= 3:
                        mac_candidate = parts[2].strip().strip('"').upper().replace("-", ":")
                        if mac_candidate and len(mac_candidate) == 17 and mac_candidate not in devices:
                            local_mac = mac_candidate
                            break
            except:
                pass

            if not local_mac:
                try:
                    ipconfig_result = subprocess.run(
                        [_win_cmd("ipconfig"), "/all"],
                        capture_output=True, text=True, timeout=5
                    )
                    sections = ipconfig_result.stdout.split("\r\n\r\n")
                    for section in sections:
                        if local_ip in section:
                            mac_match = re_module.search(
                                r'Physical Address[\s.]*:\s+([\dA-Fa-f]{2}-[\dA-Fa-f]{2}-[\dA-Fa-f]{2}-[\dA-Fa-f]{2}-[\dA-Fa-f]{2}-[\dA-Fa-f]{2})',
                                section
                            )
                            if mac_match:
                                local_mac = mac_match.group(1).upper().replace("-", ":")
                                break
                except:
                    pass

            if local_mac:
                local_hostname = socket.gethostname()
                devices[local_mac] = {
                    "ip": local_ip,
                    "hostname": local_hostname,
                    "iface": "WiFi"
                }
    except:
        pass

    return devices

def _scan_network_linux(subnet):
    """Linux/WSL scanner using ip neigh."""
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=10
        )
        neigh_output = result.stdout
    except Exception as e:
        print(f"   ❌ Neighbor scan failed (ip neigh): {e}")
        return {}

    devices = {}
    # Example: 192.168.0.12 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    neigh_pattern = r'(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)(?:\s+lladdr\s+([0-9a-fA-F:]{17}))?\s+(\S+)'

    for match in re_module.finditer(neigh_pattern, neigh_output):
        ip = match.group(1)
        iface = match.group(2)
        mac = (match.group(3) or "").upper()
        state = match.group(4).upper()

        if not ip.startswith(f"{subnet}."):
            continue
        if not mac or state in ("FAILED", "INCOMPLETE"):
            continue

        last_octet = int(ip.split(".")[-1])
        if last_octet in (0, 1, 255):
            continue

        hostname = f"Device-{last_octet}"
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            pass

        devices[mac] = {
            "ip": ip,
            "hostname": hostname,
            "iface": iface
        }

    return devices




def _load_device_name_overrides():
    """Load optional name overrides from JSON mapping by MAC/IP key."""
    try:
        if not os.path.exists(DEVICE_NAME_FILE):
            return {}
        with open(DEVICE_NAME_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _apply_device_name_overrides(devices):
    """Apply overrides where keys match device key or IP."""
    overrides = _load_device_name_overrides()
    if not overrides:
        return devices

    for key, info in devices.items():
        ip = info.get("ip")
        if key in overrides and overrides[key]:
            info["hostname"] = str(overrides[key])
        elif ip in overrides and overrides[ip]:
            info["hostname"] = str(overrides[ip])
    return devices


def _snapshot_by_ip(snapshot):
    """Create ip->(device_key, info) map to stabilize join/leave logic."""
    ip_map = {}
    for key, info in snapshot.items():
        ip = info.get("ip")
        if ip:
            ip_map[ip] = (key, info)
    return ip_map

def scan_network(subnet=NETWORK_SUBNET):
    """Scan local network by pinging subnet then reading ARP table"""
    print("   🔍 Scanning local network...")

    # Step 1: Read neighbor table in an OS-specific way.
    if platform.system().lower().startswith("win") or _is_wsl():
        devices = _scan_network_windows(subnet)

        # On WSL/Windows ARP can be sparse until hosts are actively probed.
        if len(devices) <= 1:
            print("   ⚠️ Low device count from ARP cache, running active ping sweep...")
            workers = 24 if _is_wsl() else 48
            _ping_sweep_subnet(subnet, max_workers=workers)
            devices = _scan_network_windows(subnet)
    else:
        # Keep Linux behavior: warm neighbor cache then read ip neigh.
        threads = []
        for i in range(2, 255):
            ip = f"{subnet}.{i}"
            t = threading.Thread(target=ping_host, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=3)

        devices = _scan_network_linux(subnet)

    devices = _apply_device_name_overrides(devices)

    print(f"   ✅ Found {len(devices)} devices on network")
    return devices

# ── Alert Functions ──────────────────────────────────────
def load_trusted():
    try:
        with open(TRUSTED_FILE) as f:
            return json.load(f)
    except:
        return {}

def save_trusted(d):
    with open(TRUSTED_FILE, "w") as f:
        json.dump(d, f, indent=2)

def device_label(mac, trusted):
    status = trusted.get(mac, "unknown")
    if status == "trusted":
        return "✅ TRUSTED"
    elif status == "blocked":
        return "🚫 BLOCKED"
    else:
        return "❓ UNKNOWN"

def send_join_alert(mac, info, trusted):
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    iface = "📶 WiFi" if "wlan" in info["iface"].lower() or info["iface"] == "WiFi" else "🔌 LAN"
    label = device_label(mac, trusted)
    
    msg = (
        f"🟢 *DEVICE JOINED* — {label}\n\n"
        f"📛 Name: `{info['hostname']}`\n"
        f"🌐 IP: `{info['ip']}`\n"
        f"🔑 MAC: `{mac}`\n"
        f"{iface}\n"
        f"🕐 {time_str}\n\n"
        f"Reply:\n"
        f"`trust {mac}` — mark as trusted\n"
        f"`block {mac}` — mark as intruder"
    )
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"},
            timeout=5
        )
        print(f"🟢 JOINED [{label}]: {info['hostname']} | {info['ip']} | {mac}")
    except Exception as e:
        print(f"❌ Telegram error: {e}")

def send_leave_alert(mac, info, trusted):
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    iface = "📶 WiFi" if "wlan" in info["iface"].lower() or info["iface"] == "WiFi" else "🔌 LAN"
    label = device_label(mac, trusted)
    
    msg = (
        f"🔴 *DEVICE LEFT* — {label}\n\n"
        f"📛 Name: `{info['hostname']}`\n"
        f"🌐 IP: `{info['ip']}`\n"
        f"🔑 MAC: `{mac}`\n"
        f"{iface}\n"
        f"🕐 {time_str}"
    )
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"},
            timeout=5
        )
        print(f"🔴 LEFT [{label}]: {info['hostname']} | {info['ip']} | {mac}")
    except Exception as e:
        print(f"❌ Telegram error: {e}")

# ── Telegram Helpers ─────────────────────────────────────
def send_telegram(text, parse_mode="Markdown"):
    """Send a message to Telegram chat."""
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": text, "parse_mode": parse_mode},
            timeout=10
        )
    except Exception as e:
        print(f"❌ Telegram send error: {e}")

def resolve_device(identifier, devices):
    """Resolve a device by name, MAC, IP, or list number."""
    identifier = identifier.strip()
    if not identifier:
        return None, None

    # Exact MAC match
    mac_upper = identifier.upper().replace("-", ":")
    if mac_upper in devices:
        return mac_upper, devices[mac_upper]

    # Exact IP match
    for mac, info in devices.items():
        if info["ip"] == identifier:
            return mac, info

    # Number from device list
    try:
        num = int(identifier)
        device_list = list(devices.items())
        if 1 <= num <= len(device_list):
            return device_list[num - 1]
    except ValueError:
        pass

    # Hostname match (case-insensitive, partial)
    id_lower = identifier.lower()
    for mac, info in devices.items():
        if id_lower in info["hostname"].lower():
            return mac, info

    return None, None

def format_device_list(devices, trusted):
    """Format device list for Telegram display."""
    if not devices:
        return "No devices connected."
    lines = ["📡 *Connected Devices:*\n"]
    for i, (mac, info) in enumerate(devices.items(), 1):
        status = device_label(mac, trusted)
        blocked = "🔒" if net_blocker.is_blocked(info["ip"]) else ""
        lines.append(
            f"{i}. *{info['hostname']}* {blocked}\n"
            f"    IP: `{info['ip']}` | MAC: `{mac}`\n"
            f"    {status}"
        )
    lines.append(f"\n_Total: {len(devices)} devices_")
    return "\n".join(lines)

def build_help_message():
    """Build the help text for Telegram."""
    ai_status = "✅ Enabled" if OPENROUTER_API_KEY else "❌ Disabled (no API key)"
    blocker_status = "✅ Available" if net_blocker.is_available() else "❌ Not available (install scapy)"
    return (
        "🛡️ *Network Monitor Commands*\n\n"
        "📋 *Device Info:*\n"
        "`/devices` — List all connected devices\n"
        "`/status` — Monitoring stats\n\n"
        "🔒 *Control:*\n"
        "`/block <name/MAC/IP/#>` — Block device internet\n"
        "`/unblock <name/MAC/IP/#>` — Restore device internet\n"
        "`/trust <name/MAC/IP/#>` — Mark as trusted\n"
        "`/remove <name/MAC/IP/#>` — Reset to unknown\n"
        "`/unblockall` — Unblock all devices\n\n"
        "💡 *Tips:*\n"
        "• Use device number from `/devices` list\n"
        "• Or use hostname: `/block Esos-iPhone`\n\n"
        f"🤖 AI: {ai_status}\n"
        f"🚫 Blocker: {blocker_status}"
    )

def execute_action(action, target_str, trusted, devices):
    """Execute a parsed command action. Returns response message."""
    if action == "list":
        return format_device_list(devices, trusted)

    elif action == "status":
        blocked_list = net_blocker.get_blocked()
        return (
            f"📊 *Monitor Status*\n\n"
            f"📡 Devices online: {len(devices)}\n"
            f"🚫 Devices blocked: {len(blocked_list)}\n"
            f"🔄 Scan interval: {INTERVAL}s\n"
            f"🤖 AI: {'Enabled' if OPENROUTER_API_KEY else 'Disabled'}\n"
            f"🔒 Blocker: {'Ready' if net_blocker.is_available() else 'N/A'}"
        )

    elif action == "help":
        return build_help_message()

    elif action in ("block", "unblock", "trust", "remove"):
        if not target_str:
            return f"⚠️ Usage: `/{action} <name/MAC/IP/#>`"
        mac, info = resolve_device(target_str, devices)
        if not mac:
            return f"⚠️ Device `{target_str}` not found. Send `/devices` to see the list."

        if action == "block":
            # ARP spoof block + label
            success, msg = net_blocker.block_device(info["ip"], GATEWAY)
            trusted[mac] = "blocked"
            save_trusted(trusted)
            if success:
                return f"🚫 *BLOCKED* `{info['hostname']}` (`{info['ip']}`)\n\nInternet access cut off.\nUndo: `/unblock {info['hostname']}`"
            else:
                return f"🚫 Labeled `{info['hostname']}` as blocked.\n⚠️ {msg}"

        elif action == "unblock":
            success, msg = net_blocker.unblock_device(info["ip"])
            if mac in trusted and trusted[mac] == "blocked":
                trusted.pop(mac, None)
                save_trusted(trusted)
            if success:
                return f"✅ *UNBLOCKED* `{info['hostname']}` (`{info['ip']}`)\n\nInternet access restored."
            else:
                return f"⚠️ {msg}"

        elif action == "trust":
            trusted[mac] = "trusted"
            save_trusted(trusted)
            return f"✅ `{info['hostname']}` marked as *trusted*."

        elif action == "remove":
            trusted.pop(mac, None)
            save_trusted(trusted)
            return f"🔄 `{info['hostname']}` reset to *unknown*."

    elif action == "unblockall":
        results = net_blocker.unblock_all()
        return "✅ All devices unblocked.\n" + "\n".join(results) if results else "No devices were blocked."

    return None

# ── Enhanced Telegram Command Handler ────────────────────
def check_telegram_replies(trusted, devices=None):
    if devices is None:
        devices = {}
    try:
        resp = requests.get(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates",
            params={"offset": trusted.get("_last_update_id", 0) + 1, "timeout": 1},
            timeout=5
        )
        updates = resp.json().get("result", [])

        for update in updates:
            update_id = update["update_id"]
            trusted["_last_update_id"] = update_id

            msg = update.get("message", {})
            text = msg.get("text", "").strip()
            chat = str(msg.get("chat", {}).get("id", ""))

            if chat != str(CHAT_ID) or not text:
                continue

            print(f"📩 Telegram: {text}")

            # Parse command and arguments
            parts = text.split(None, 1)
            command = parts[0].lower().lstrip("/")
            args = parts[1].strip() if len(parts) > 1 else ""

            # Direct command matching
            if command in ("devices", "list"):
                reply = execute_action("list", "", trusted, devices)
            elif command in ("block",):
                reply = execute_action("block", args, trusted, devices)
            elif command in ("unblock",):
                reply = execute_action("unblock", args, trusted, devices)
            elif command in ("trust",):
                reply = execute_action("trust", args, trusted, devices)
            elif command in ("remove",):
                reply = execute_action("remove", args, trusted, devices)
            elif command in ("status",):
                reply = execute_action("status", "", trusted, devices)
            elif command in ("help", "start"):
                reply = execute_action("help", "", trusted, devices)
            elif command in ("unblockall",):
                reply = execute_action("unblockall", "", trusted, devices)
            else:
                # AI fallback for natural language
                if OPENROUTER_API_KEY:
                    print(f"🤖 Sending to AI: {text}")
                    dev_context = format_device_list(devices, trusted)
                    blocked = net_blocker.get_blocked()
                    ai_result, err = ai_handler.interpret_message(
                        text, dev_context, blocked,
                        OPENROUTER_API_KEY, OPENROUTER_MODEL
                    )
                    if err:
                        reply = f"⚠️ AI error: {err}"
                    elif ai_result:
                        ai_action = ai_result.get("action", "chat")
                        ai_target = ai_result.get("target", "")
                        ai_reply = ai_result.get("reply", "")

                        if ai_action == "chat":
                            reply = f"🤖 {ai_reply}"
                        else:
                            result = execute_action(ai_action, ai_target, trusted, devices)
                            reply = result if result else f"🤖 {ai_reply}"
                    else:
                        reply = "⚠️ Could not process that message."
                else:
                    reply = f"❓ Unknown command: `{command}`\n\nSend `/help` for available commands."

            if reply:
                send_telegram(reply)
                print(f"📤 Reply sent: {reply[:80]}...")

        save_trusted(trusted)
    except Exception as e:
        print(f"Telegram error: {e}")

    return trusted

# ── Main ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("🔐 Logging into ZLT X20 router...")
    session_id = login()
    
    if not session_id:
        print("\n⚠️  Could not authenticate, will use network scan")
        use_router_api = False
    else:
        print(f"\n✅ Session acquired: {session_id}")
        use_router_api = True
    
    trusted = load_trusted()
    login_timer = time.time()
    
    print("\n📡 Taking initial snapshot...")
    previous_snapshot = {}
    
    # Try router API first, then fall back to network scan
    if use_router_api:
        previous_snapshot = get_devices(session_id)
    
    if not previous_snapshot:
        print("📡 Using network scan to discover devices...")
        previous_snapshot = scan_network()
    
    if previous_snapshot:
        print(f"✅ Found {len(previous_snapshot)} devices")
        for mac, info in previous_snapshot.items():
            print(f"   - {info['hostname']} ({mac}) - {info['ip']}")
            send_join_alert(mac, info, trusted)
    else:
        print("⚠️  No devices found on network")
    
    # Send startup message to Telegram
    send_telegram(
        f"🟢 *Network Monitor Started*\n\n"
        f"📡 Tracking {len(previous_snapshot)} devices\n"
        f"🔄 Scan interval: {INTERVAL}s\n"
        f"🤖 AI: {'Enabled' if OPENROUTER_API_KEY else 'Disabled'}\n"
        f"🔒 Blocker: {'Ready' if net_blocker.is_available() else 'Label-only'}\n\n"
        f"Send `/help` for commands."
    )
    
    print(f"\n🟢 Monitoring started. Scanning every {INTERVAL} seconds.\n")
    
    while True:
        try:
            # Refresh router session periodically
            if use_router_api and time.time() - login_timer > 600:
                print("\n🔄 Refreshing session...")
                session_id = login()
                login_timer = time.time()
            
            trusted = check_telegram_replies(trusted, previous_snapshot)
            
            # Try router API first, fall back to network scan
            current_snapshot = {}
            if use_router_api:
                current_snapshot = get_devices(session_id)
            
            if not current_snapshot:
                current_snapshot = scan_network()
            
            if current_snapshot:
                prev_by_ip = _snapshot_by_ip(previous_snapshot)
                curr_by_ip = _snapshot_by_ip(current_snapshot)
                joined_ips = []
                left_ips = []

                # Devices that JOINED (or re-joined)
                for ip, (dev_key, info) in curr_by_ip.items():
                    if ip not in prev_by_ip:
                        joined_ips.append(ip)
                        send_join_alert(dev_key, info, trusted)

                # Devices that LEFT
                for ip, (dev_key, info) in prev_by_ip.items():
                    if ip not in curr_by_ip:
                        left_ips.append(ip)
                        send_leave_alert(dev_key, info, trusted)

                if joined_ips or left_ips:
                    print(f"📉 Delta joined={joined_ips} left={left_ips}")
                
                previous_snapshot = current_snapshot
                print(f"📊 Currently tracking {len(previous_snapshot)} devices")
            else:
                print("⚠️  Scan returned no devices, keeping previous snapshot")
            
            time.sleep(INTERVAL)
            
        except KeyboardInterrupt:
            print("\n👋 Monitoring stopped — unblocking all devices...")
            net_blocker.unblock_all()
            send_telegram("🔴 *Network Monitor Stopped*")
            break
        except Exception as e:
            print(f"⚠️  Error: {e}")
            time.sleep(INTERVAL)