import requests
import re
from bs4 import BeautifulSoup
import os
from env_config import load_env_local

load_env_local()

router = os.getenv("ROUTER_URL", "http://192.168.0.1")
session = requests.Session()

print("🔍 Analyzing ZLT X20 router login mechanism\n")
print("=" * 60)

# Get the main page
resp = session.get(f"{router}/")
soup = BeautifulSoup(resp.text, 'html.parser')

# Look for all forms
print("📝 Found forms:")
forms = soup.find_all('form')
for i, form in enumerate(forms):
    print(f"\nForm {i+1}:")
    print(f"  Action: {form.get('action', 'NOT SPECIFIED')}")
    print(f"  Method: {form.get('method', 'GET')}")
    
    # Get all input fields
    inputs = form.find_all('input')
    for inp in inputs:
        inp_type = inp.get('type', 'text')
        inp_name = inp.get('name', '')
        inp_id = inp.get('id', '')
        print(f"    Input: type={inp_type}, name={inp_name}, id={inp_id}")

# Look for JavaScript login functions
print("\n" + "=" * 60)
print("🔍 Looking for JavaScript login functions...")

scripts = soup.find_all('script')
for script in scripts:
    if script.string:
        js_code = script.string
        
        # Look for login related functions
        if 'login' in js_code.lower():
            print("\nFound login-related JavaScript:")
            
            # Look for function definitions
            func_matches = re.findall(r'function\s+(\w*login\w*)\s*\([^)]*\)\s*\{[^}]*\}', js_code, re.IGNORECASE)
            for func in func_matches:
                print(f"  - Function: {func}()")
            
            # Look for API endpoints
            api_matches = re.findall(r'["\'](/[^"\']+\.cgi[^"\']*)["\']', js_code)
            for api in set(api_matches):
                print(f"  - API endpoint: {api}")
            
            # Look for URL patterns
            url_matches = re.findall(r'url\s*:\s*["\']([^"\']+)["\']', js_code)
            for url in set(url_matches):
                print(f"  - URL: {url}")

# Look for embedded data
print("\n" + "=" * 60)
print("🔍 Looking for configuration data...")

# Look for var declarations
var_pattern = r'var\s+(\w+)\s*=\s*({[^;]+}|\[[^\;]+\]|"[^"]+"|\d+)'
vars_found = re.findall(var_pattern, resp.text)
for var_name, var_value in vars_found[:10]:
    if len(var_value) < 200:  # Only show short values
        print(f"  {var_name} = {var_value[:100]}")

# Try to find the actual login endpoint by inspecting network patterns
print("\n" + "=" * 60)
print("🌐 Trying common ZLT X20 endpoints based on known patterns...")

# Known ZLT X20 endpoints from research
zlt_endpoints = [
    "/cgi-bin/login",
    "/cgi-bin/logout", 
    "/cgi-bin/get_dhcp_list",
    "/cgi-bin/get_status",
    "/goform/goform_set_cmd_process",
    "/cgi-bin/luci",
    "/cgi-bin/webcm",
    "/cgi-bin/http.cgi",
    "/api/auth",
    "/api/login",
]

for endpoint in zlt_endpoints:
    try:
        # Try GET first
        resp = session.get(f"{router}{endpoint}", timeout=3)
        if resp.status_code != 404:
            print(f"  ✅ Found: {endpoint} (Status: {resp.status_code})")
            
            # If it's a POST endpoint, try to see what it expects
            if resp.status_code == 405:  # Method not allowed
                print(f"     → This endpoint expects POST requests")
                
                # Try a test POST
                test_data = {"test": "1"}
                post_resp = session.post(f"{router}{endpoint}", data=test_data, timeout=3)
                print(f"     POST test response: {post_resp.status_code}")
                
    except Exception as e:
        pass

# Try to get device list from main page source (might be embedded)
print("\n" + "=" * 60)
print("🔍 Searching page source for device information...")

# Look for MAC addresses in the page
mac_pattern = r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})'
macs = re.findall(mac_pattern, resp.text, re.IGNORECASE)

if macs:
    print(f"  Found MAC addresses in page: {', '.join(set(macs))}")
else:
    print("  No MAC addresses found in initial page (they load dynamically)")

# Look for data attributes that might contain device info
data_pattern = r'data-[a-z-]+="[^"]+"'
data_attrs = re.findall(data_pattern, resp.text)
if data_attrs:
    print(f"  Found data attributes: {data_attrs[:5]}")

print("\n" + "=" * 60)
print("💡 RECOMMENDATION:")
print("Since the router uses JavaScript to load content dynamically,")
print("the best approach is to use Selenium to automate a real browser.")
print("\nTo install Selenium and Chrome for WSL:")
print("  sudo apt-get update")
print("  sudo apt-get install -y chromium-browser")
print("  pip install selenium")
print("\nOr we can create a simpler solution that uses the fallback")
print("device list from your screenshot while you investigate the API.")

# Offer to save the current page for manual inspection
save = input("\n📁 Save the main page HTML for manual inspection? (y/n): ")
if save.lower() == 'y':
    with open("zlt_x20_main_page.html", "w", encoding='utf-8') as f:
        f.write(resp.text)
    print("✅ Saved to 'zlt_x20_main_page.html'")
    print("   Open this file in a browser and inspect the JavaScript")