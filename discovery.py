import requests
import json
import hashlib
import time
import os
from env_config import load_env_local

load_env_local()

router = os.getenv("ROUTER_URL", "http://192.168.0.1")
username = os.getenv("ROUTER_USERNAME", "admin")
password = os.getenv("ROUTER_PASSWORD", "")
session = requests.Session()

print("🔍 Detailed analysis of /cgi-bin/http.cgi\n")
print("=" * 70)

# First, let's see what headers the router expects
print("1. Testing with different content types...")
content_types = [
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain"
]

for ct in content_types:
    try:
        headers = {"Content-Type": ct}
        test_data = {"test": "value"}
        
        if ct == "application/x-www-form-urlencoded":
            resp = session.post(f"{router}/cgi-bin/http.cgi", data=test_data, headers=headers, timeout=5)
        else:
            resp = session.post(f"{router}/cgi-bin/http.cgi", json=test_data, headers=headers, timeout=5)
        
        print(f"   {ct}: Status {resp.status_code}")
        if resp.status_code == 200 and resp.text:
            print(f"      Response: {resp.text[:100]}")
    except Exception as e:
        print(f"   {ct}: Error - {e}")

print("\n2. Trying different command values without authentication...")
# Try a wider range of commands
for cmd in range(1, 20):
    try:
        test_data = {"cmd": cmd}
        resp = session.post(f"{router}/cgi-bin/http.cgi", json=test_data, timeout=5)
        
        if resp.status_code == 200 and resp.text and len(resp.text) > 5:
            print(f"   cmd={cmd}: {resp.status_code} - {len(resp.text)} bytes")
            try:
                data = resp.json()
                print(f"      Response: {json.dumps(data, indent=2)[:200]}")
            except:
                print(f"      Raw: {resp.text[:100]}")
    except:
        pass

print("\n3. Checking if the router needs specific parameters...")
# Common parameter combinations
test_params = [
    {"cmd": 100, "method": "GET"},
    {"cmd": 100, "method": "POST"},
    {"cmd": 100, "method": "GET", "sessionId": ""},
    {"cmd": 100, "method": "POST", "sessionId": ""},
    {"cmd": 100, "method": "POST", "username": username},
    {"cmd": 100, "method": "POST", "username": username, "password": ""},
]

for params in test_params:
    try:
        resp = session.post(f"{router}/cgi-bin/http.cgi", json=params, timeout=5)
        if resp.status_code == 200 and resp.text:
            print(f"\n   Params: {params}")
            print(f"   Response: {resp.text[:200]}")
            
            # Try to parse as JSON
            try:
                data = resp.json()
                print(f"   JSON: {json.dumps(data, indent=2)[:300]}")
            except:
                pass
    except Exception as e:
        print(f"   Error with {params}: {e}")

print("\n4. Trying to find the correct login format...")
# Try different login formats based on common router APIs
login_formats = [
    # Format 1: Standard
    {
        "cmd": 100,
        "username": username,
        "password": password
    },
    # Format 2: With method
    {
        "cmd": 100,
        "method": "login",
        "username": username,
        "password": password
    },
    # Format 3: With action
    {
        "action": "login",
        "username": username,
        "password": password
    },
    # Format 4: With goformId
    {
        "goformId": "LOGIN",
        "username": username,
        "password": password
    },
    # Format 5: With hashed password (MD5)
    {
        "cmd": 100,
        "username": username,
        "password": hashlib.md5(password.encode()).hexdigest()
    },
    # Format 6: With hashed password (SHA256)
    {
        "cmd": 100,
        "username": username,
        "password": hashlib.sha256(password.encode()).hexdigest()
    },
]

for i, login_data in enumerate(login_formats, 1):
    try:
        print(f"\n   Attempt {i}: {login_data}")
        resp = session.post(f"{router}/cgi-bin/http.cgi", json=login_data, timeout=5)
        print(f"   Status: {resp.status_code}")
        
        if resp.status_code == 200 and resp.text:
            print(f"   Response: {resp.text[:200]}")
            
            # Check for session ID in response
            try:
                data = resp.json()
                if "sessionId" in data:
                    print(f"   ✅ GOT SESSION ID: {data['sessionId']}")
                    if data['sessionId'] and data['sessionId'] != "null":
                        print(f"   🎉 LOGIN SUCCESSFUL!")
                        break
            except:
                pass
    except Exception as e:
        print(f"   Error: {e}")

print("\n5. Checking if we can get device info without login...")
# Try to get device list directly
device_commands = [401, 402, 403, 404, 405, 410, 420, 430]

for cmd in device_commands:
    try:
        device_data = {"cmd": cmd, "method": "GET"}
        resp = session.post(f"{router}/cgi-bin/http.cgi", json=device_data, timeout=5)
        
        if resp.status_code == 200 and resp.text and len(resp.text) > 50:
            print(f"\n   cmd={cmd}: Got response ({len(resp.text)} bytes)")
            try:
                data = resp.json()
                print(f"   Response structure: {list(data.keys()) if isinstance(data, dict) else 'list'}")
                
                # Look for device-related keys
                device_keys = ["dhcp_list", "device_list", "hosts", "clients", "stations", "mac", "ip"]
                for key in device_keys:
                    if key in str(data).lower():
                        print(f"   🎯 Found '{key}' in response!")
                        print(f"   Data: {json.dumps(data, indent=2)[:500]}")
                        break
            except:
                print(f"   Raw: {resp.text[:200]}")
    except Exception as e:
        pass

print("\n" + "=" * 70)
print("💡 If none of the above worked, the router might require:")
print("   1. A specific sequence of requests (visit page first, then login)")
print("   2. Cookies from the initial page load")
print("   3. CSRF tokens from the HTML")

print("\n📝 Let's try to capture the exact login flow by visiting the main page first...")

# Get the main page first to capture cookies and tokens
print("\n6. Capturing initial page cookies and tokens...")
try:
    # Visit main page
    main_resp = session.get(f"{router}/")
    print(f"   Main page status: {main_resp.status_code}")
    print(f"   Cookies after main page: {session.cookies.get_dict()}")
    
    # Look for CSRF token in main page
    if '<input' in main_resp.text:
        import re
        csrf_pattern = r'name=["\'](?:csrf|token|_token)["\']\s+value=["\']([^"\']+)["\']'
        csrf_tokens = re.findall(csrf_pattern, main_resp.text, re.IGNORECASE)
        if csrf_tokens:
            print(f"   Found CSRF tokens: {csrf_tokens}")
    
    # Now try login again with cookies
    login_data = {
        "cmd": 100,
        "username": username,
        "password": password
    }
    resp = session.post(f"{router}/cgi-bin/http.cgi", json=login_data, timeout=5)
    print(f"\n   Login with cookies: Status {resp.status_code}")
    if resp.status_code == 200 and resp.text:
        print(f"   Response: {resp.text[:200]}")
        try:
            data = resp.json()
            if data.get("sessionId"):
                print(f"   ✅ Session ID: {data['sessionId']}")
        except:
            pass
            
except Exception as e:
    print(f"   Error: {e}")

print("\n✅ Discovery complete!")