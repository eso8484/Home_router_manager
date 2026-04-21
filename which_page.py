import requests
from bs4 import BeautifulSoup
import time
import os
from env_config import load_env_local

load_env_local()

router = os.getenv("ROUTER_URL", "http://192.168.0.1")
session = requests.Session()

# Try to access the main pages you showed in the screenshot
pages = [
    "/",
    "/index.html",
    "/home.html",
    "/status.html",
    "/device.html",
    "/wlan.html",
    "/network.html"
]

print("Testing accessible pages...\n")

for page in pages:
    try:
        print(f"Testing: {page}")
        resp = session.get(f"{router}{page}", timeout=5, allow_redirects=True)
        print(f"  Status: {resp.status_code}")
        
        if resp.status_code == 200 and resp.text:
            print(f"  Content length: {len(resp.text)} chars")
            
            # Check if it contains device information
            if "Connected Device" in resp.text or "MAC" in resp.text:
                print(f"  ✅ FOUND DEVICE TABLE HERE!")
                # Save the page for analysis
                with open(f"page_{page.replace('/', '_')}.html", "w") as f:
                    f.write(resp.text)
                print(f"  Saved to: page_{page.replace('/', '_')}.html")
            elif "MTN Broadband" in resp.text:
                print(f"  ✅ Found router main page")
                
        time.sleep(0.5)
        
    except Exception as e:
        print(f"  Error: {e}")
    
    print()