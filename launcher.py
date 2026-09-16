"""Windows GUI launcher used by PyInstaller.

Double-clicking the generated executable starts the localhost Web console.
"""
import sys

from api_scan_tool.cli import main


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.append("web")
    elif sys.argv[1].startswith("-"):
        sys.argv.insert(1, "web")
    main()
