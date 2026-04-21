import os
from pathlib import Path


def load_env_local(env_file: str = ".env.local") -> None:
    """Load KEY=VALUE pairs from .env.local into process environment."""
    path = Path(__file__).resolve().parent / env_file
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key and key not in os.environ:
            os.environ[key] = value
