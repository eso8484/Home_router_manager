# Monitors Network

A Python-based home network monitor for ZLT X20-style routers with Telegram alerts, optional AI command parsing, and optional ARP-based device blocking.

## Features

- Detects devices joining and leaving your network
- Sends alerts and command responses to Telegram
- Supports trust and block labels per device
- Optional ARP spoofing blocker using scapy
- Optional natural-language command handling via OpenRouter
- Router API mode with fallback to local network scan

## Project Files

- router_monitor.py: Main monitoring script
- net_blocker.py: ARP-based internet blocking helper
- ai_handler.py: OpenRouter command interpreter
- env_config.py: Loads environment values from .env.local
- trusted_devices.json: Local trust/block state store
- debug.py, discovery.py, login.py, which_page.py: Router investigation/debug scripts

## Prerequisites

- Python 3.10+
- pip
- Network access to your router
- Telegram bot token and chat ID

Optional:

- Npcap (Windows) for scapy-based ARP blocking
- OpenRouter API key for AI message parsing

## Setup

1. Clone or copy this repository.
2. Open a terminal in the project folder.
3. Create and activate a virtual environment.
4. Install required packages.

Example setup commands:

For Linux or WSL:

python3 -m venv .venv
source .venv/bin/activate
pip install requests beautifulsoup4 scapy

For Windows PowerShell:

python -m venv .venv
.venv\Scripts\Activate.ps1
pip install requests beautifulsoup4 scapy

## Environment Configuration

The app reads configuration from .env.local.

Current variables used:

- ROUTER_URL
- ROUTER_USERNAME
- ROUTER_PASSWORD
- GATEWAY_IP
- NETWORK_SUBNET
- TELEGRAM_BOT_TOKEN
- TELEGRAM_CHAT_ID
- MONITOR_INTERVAL
- TRUSTED_FILE
- OPENROUTER_API_KEY
- OPENROUTER_MODEL

Create or edit .env.local in the project root and set your own values.

Security note:

- Do not commit .env.local
- Rotate any token or key that was ever committed/shared

## Run

Start the monitor:

python router_monitor.py

What it does on startup:

- Tries router login and API-based device discovery
- Falls back to subnet/ARP scan if API mode fails
- Sends startup status to Telegram
- Polls Telegram for commands and monitors device changes

## Telegram Commands

Supported commands include:

- /devices or /list
- /status
- /help
- /block <name or MAC or IP or number>
- /unblock <name or MAC or IP or number>
- /trust <name or MAC or IP or number>
- /remove <name or MAC or IP or number>
- /unblockall

If OPENROUTER_API_KEY is set, non-command messages can be interpreted using AI.

## Troubleshooting

Issue: no devices found

- Verify ROUTER_URL and subnet values
- Confirm router credentials in .env.local
- Ensure your machine is on the same network

Issue: Telegram not responding

- Verify TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
- Confirm the bot can message that chat

Issue: blocker not working

- Install scapy and Npcap
- Run terminal with admin privileges when required

Issue: first git push helper error about HEAD

- This means the repo had no initial commit yet
- Use the updated user-level g script if configured, or commit once manually

## Suggested First Run Checklist

1. Fill .env.local with your real values
2. Activate virtual environment
3. Install dependencies
4. Run python router_monitor.py
5. Send /help in Telegram chat
6. Validate join/leave alerts from your network

## Notes for Contributors

- Keep credentials and keys only in .env.local
- Avoid committing generated local debug HTML files
- Prefer updating trusted_devices.json only through script actions
