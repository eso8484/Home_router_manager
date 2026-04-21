import hashlib
import time
import json
import sys
import os
import re as re_module
import subprocess
import socket
import threading
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

# ── OpenRouter AI Config (optional, for natural language) ─
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free")

session = requests.Session()

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
    """Ping a single host to populate ARP table (Windows)"""
    try:
        subprocess.run(
            ["ping", "-n", "1", "-w", "500", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
    except:
        pass

def scan_network(subnet=NETWORK_SUBNET):
    """Scan local network by pinging subnet then reading ARP table"""
    print("   🔍 Scanning local network...")

    # Step 1: Ping sweep to populate ARP table with all active hosts
    threads = []
    for i in range(2, 255):  # skip .0 and .1 (gateway)
        ip = f"{subnet}.{i}"
        t = threading.Thread(target=ping_host, args=(ip,), daemon=True)
        threads.append(t)
        t.start()

    # Wait for pings to finish
    for t in threads:
        t.join(timeout=3)

    # Step 2: Read the ARP table
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=10
        )
        arp_output = result.stdout
    except Exception as e:
        print(f"   ❌ ARP scan failed: {e}")
        return {}

    # Step 3: Parse ARP output
    # Windows format: "  192.168.0.100       98-54-1b-f9-e6-ce     dynamic"
    devices = {}
    arp_pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+(\w+)'

    for match in re_module.finditer(arp_pattern, arp_output):
        ip = match.group(1)
        mac = match.group(2).upper().replace("-", ":")
        entry_type = match.group(3)

        # Only include dynamic entries in our subnet
        if entry_type.lower() != "dynamic":
            continue
        if not ip.startswith(f"{subnet}."):
            continue

        # Skip gateway and broadcast
        last_octet = int(ip.split(".")[-1])
        if last_octet in (0, 1, 255):
            continue

        # Skip multicast/broadcast MACs
        if mac.startswith("FF:FF") or mac.startswith("01:00") or mac.startswith("33:33"):
            continue

        # Try to resolve hostname
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

    # Step 4: Add THIS computer (it never appears in its own ARP table)
    try:
        # Get local IP from ARP interface header: "Interface: 192.168.0.100 --- 0x5"
        iface_pattern = r'Interface:\s+(' + subnet.replace('.', r'\.') + r'\.\d+)'
        iface_match = re_module.search(iface_pattern, arp_output)
        if iface_match:
            local_ip = iface_match.group(1)
            local_mac = None

            # Method 1: getmac - find the connected (non-disconnected) adapter
            try:
                mac_result = subprocess.run(
                    ["getmac", "/fo", "csv", "/nh", "/v"],
                    capture_output=True, text=True, timeout=5
                )
                for line in mac_result.stdout.strip().split("\n"):
                    line = line.strip()
                    if not line or "disconnected" in line.lower():
                        continue
                    # Format: "Name","Description","MAC","Transport"
                    parts = line.split(",")
                    if len(parts) >= 3:
                        mac_candidate = parts[2].strip().strip('"').upper().replace("-", ":")
                        if mac_candidate and len(mac_candidate) == 17 and mac_candidate not in devices:
                            local_mac = mac_candidate
                            break
            except:
                pass

            # Method 2: ipconfig /all - find MAC in the section containing our IP
            if not local_mac:
                try:
                    ipconfig_result = subprocess.run(
                        ["ipconfig", "/all"],
                        capture_output=True, text=True, timeout=5
                    )
                    # Split into adapter sections and find the one with our IP
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
                # Devices that JOINED (or re-joined)
                for mac, info in current_snapshot.items():
                    if mac not in previous_snapshot:
                        send_join_alert(mac, info, trusted)
                
                # Devices that LEFT
                for mac, info in previous_snapshot.items():
                    if mac not in current_snapshot:
                        send_leave_alert(mac, info, trusted)
                
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