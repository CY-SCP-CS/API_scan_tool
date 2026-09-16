"""Runtime configuration helpers shared by the CLI, web app and packaged EXE."""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv


def load_runtime_env() -> None:
    """Load a local .env without ever overwriting a real environment variable.

    In a PyInstaller build the editable .env belongs next to the EXE; in a
    source checkout it belongs at the project root. The current directory is
    also checked to make command-line use convenient.
    """
    candidates = [Path.cwd() / ".env"]
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / ".env")
    else:
        candidates.append(Path(__file__).resolve().parents[1] / ".env")
    for path in candidates:
        if path.is_file():
            load_dotenv(path, override=False)
