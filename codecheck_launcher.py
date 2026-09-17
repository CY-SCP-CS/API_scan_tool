"""Windowed launcher for the source-only Code Check executable."""
from __future__ import annotations

import sys
import webbrowser
from pathlib import Path

import uvicorn

from codecheck_backend import create_app


def ensure_local_env_template() -> None:
    """Create a local editable placeholder on first run, never with a real key."""
    directory = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    target = directory / ".env"
    template = directory / ".env.example"
    if not target.exists() and template.is_file():
        target.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")


if __name__ == "__main__":
    ensure_local_env_template()
    port = 8787
    if not any(arg == "--no-browser" for arg in sys.argv[1:]):
        webbrowser.open(f"http://127.0.0.1:{port}")
    uvicorn.run(create_app(), host="127.0.0.1", port=port, log_config=None, access_log=False)
