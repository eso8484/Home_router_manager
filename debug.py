import requests
import json
import hashlib
import os
from env_config import load_env_local

load_env_local()

router = os.getenv("ROUTER_URL", "http://192.168.0.1")
username = os.getenv("ROUTER_USERNAME", "admin")
password = os.getenv("ROUTER_PASSWORD", "")
session = requests.Session()

print("🔍 Debugging ZLT X20 API\n")
print("=" * 60)

# First, get the main page to establish session
print("1. Getting main page...")
resp = session.get(f"{router}/")
print(f"   Status: {resp.status_code}")
print(f"   Cookies: {session.cookies.get_dict()}")

# Try different authentication approaches
print("\n2. Trying different authentication methods...")

# Method A: Try with no password (maybe router allows device list without auth)
print("\n   Method A: No authentication, direct device list")
test_cmds = [401, 402, 403, 404, 405, 410]
for cmd in test_cmds:
    test_data = {
        "cmd": cmd,
        "method": "GET",
        "sessionId": ""
    }
    resp = session.post(f"{router}/cgi-bin/http.cgi", json=test_data)
    if resp.status_code == 200 and resp.text:
        print(f"      cmd={cmd}: {len(resp.text)} bytes")
        try:
            data = resp.json()
            if data.get("success") == True:
                print(f"      ✅ Success! Response: {json.dumps(data, indent=2)[:300]}")
        except:
            print(f"      Raw: {resp.text[:100]}")

# Method B: Try login with different password formats
print("\n   Method B: Trying login with different formats")
password_hashes = {
    "plain": password,
    "md5": hashlib.md5(password.encode()).hexdigest(),
    "sha256": hashlib.sha256(password.encode()).hexdigest(),
}

for hash_name, pwd_hash in password_hashes.items():
    print(f"\n      Testing {hash_name} hash: {pwd_hash}")
    
    login_data = {
        "cmd": 100,
        "method": "POST",
        "username": username,
        "password": pwd_hash,
        "sessionId": ""
    }
    
    resp = session.post(f"{router}/cgi-bin/http.cgi", json=login_data)
    print(f"      Status: {resp.status_code}")
    
    if resp.status_code == 200 and resp.text:
        print(f"      Response length: {len(resp.text)}")
        print(f"      Raw response: {resp.text[:200]}")
        
        try:
            data = resp.json()
            print(f"      Parsed JSON: {json.dumps(data, indent=2)[:300]}")
            
            if data.get("sessionId") and data.get("sessionId") != "null":
                print(f"      ✅ GOT SESSION! ID: {data['sessionId']}")
                
                # Try to get device list with this session
                print(f"\n      Testing device list with session...")
                device_data = {
                    "cmd": 402,
                    "method": "GET",
                    "sessionId": data['sessionId']
                }
                device_resp = session.post(f"{router}/cgi-bin/http.cgi", json=device_data)
                
                if device_resp.status_code == 200:
                    print(f"      Device list response: {device_resp.text[:500]}")
                    try:
                        devices = device_resp.json()
                        print(f"      Devices: {json.dumps(devices, indent=2)[:500]}")
                    except:
                        pass
                
                break
        except:
            pass

# Method C: Try using the sessionId from cookie
print("\n   Method C: Using sessionId from cookie")
if session.cookies.get("sessionId"):
    print(f"      Found sessionId cookie: {session.cookies.get('sessionId')}")
    device_data = {
        "cmd": 402,
        "method": "GET",
        "sessionId": session.cookies.get("sessionId")
    }
    resp = session.post(f"{router}/cgi-bin/http.cgi", json=device_data)
    print(f"      Status: {resp.status_code}")
    if resp.text:
        print(f"      Response: {resp.text[:200]}")

# Method D: Try to get the device list from the web interface directly
print("\n   Method D: Trying to fetch from web interface URLs")
web_urls = [
    "/cgi-bin/device_list",
    "/cgi-bin/dhcp_list",
    "/status.html",
    "/device.html",
    "/cgi-bin/status",
]

for url in web_urls:
    try:
        resp = session.get(f"{router}{url}")
        if resp.status_code == 200:
            print(f"      Found: {url} ({len(resp.text)} bytes)")
            if "B4:19:74:67:71:5F" in resp.text or "A8:91:3D:A4:89:D1" in resp.text:
                print(f"      ✅ Contains device MACs!")
                print(f"      Preview: {resp.text[:500]}")
                with open(f"found_{url.replace('/', '_')}.html", "w") as f:
                    f.write(resp.text)
    except:
        pass

print("\n" + "=" * 60)
print("💡 Based on the response, we can see what the API expects.")