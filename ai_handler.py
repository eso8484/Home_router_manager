"""
AI-powered natural language command interpreter.
Uses OpenRouter API (OpenAI-compatible format).
Free models like gpt-oss-120b supported.
"""

import json
import requests

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

SYSTEM_PROMPT = """You are a network security assistant controlling a home WiFi monitor via Telegram.

AVAILABLE ACTIONS (respond with exactly one JSON object):
- {"action": "block", "target": "<hostname or MAC or number>", "reply": "<message>"}
- {"action": "unblock", "target": "<hostname or MAC or number>", "reply": "<message>"}
- {"action": "trust", "target": "<hostname or MAC or number>", "reply": "<message>"}
- {"action": "remove", "target": "<hostname or MAC or number>", "reply": "<message>"}
- {"action": "list", "reply": "<message>"}
- {"action": "status", "reply": "<message>"}
- {"action": "help", "reply": "<message>"}
- {"action": "chat", "reply": "<your response>"}

Use "chat" for questions, greetings, or non-command messages.

RULES:
1. ALWAYS respond with ONLY a single valid JSON object. No markdown, no extra text.
2. For "target", use the device hostname exactly as shown in the device list.
3. If the user references a device by description (e.g. "that iPhone", "the unknown one"), match it to the closest device from the list.
4. Be concise but friendly in replies.

CONNECTED DEVICES:
{devices}

BLOCKED IPs: {blocked}"""


def interpret_message(user_message, devices_context, blocked_list,
                      api_key, model="openrouter/gpt-oss-120b"):
    """
    Send a natural language message to AI and get a structured command back.
    Returns: (action_dict, error_string)
    """
    if not api_key:
        return None, "OpenRouter API key not set"

    system_msg = (SYSTEM_PROMPT
                  .replace("{devices}", devices_context)
                  .replace("{blocked}", str(blocked_list)))
    try:
        resp = requests.post(
            OPENROUTER_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/network-monitor",
                "X-Title": "Network Monitor Bot"
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_message}
                ],
                "temperature": 0.1,
                "max_tokens": 300
            },
            timeout=20
        )

        if resp.status_code != 200:
            return None, f"API error {resp.status_code}: {resp.text[:200]}"

        result = resp.json()
        ai_text = result["choices"][0]["message"]["content"].strip()

        # Parse JSON — handle markdown code blocks
        try:
            clean = ai_text
            if "```" in clean:
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
                clean = clean.strip()
            return json.loads(clean), None
        except json.JSONDecodeError:
            return {"action": "chat", "reply": ai_text}, None

    except Exception as e:
        return None, f"AI error: {e}"
