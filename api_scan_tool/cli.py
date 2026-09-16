from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import uvicorn

from .jobs import JobManager
from .models import RunConfig
from .web import create_app


def _common_config(args: argparse.Namespace) -> RunConfig:
    return RunConfig(
        source_path=getattr(args, "source", ""),
        scan_mode=getattr(args, "scan_mode", "source"),
        target_url=args.target or "",
        openapi_url=getattr(args, "openapi_url", "") or "",
        allowlist=args.allow or [],
        ai_provider=args.ai_provider,
        model=args.model or ("deepseek-flash" if args.ai_provider == "deepseek" else ""),
        confirm_authorized=args.confirm_authorized,
        use_burp=args.use_burp,
        burp_host=args.burp_host,
        burp_port=args.burp_port,
        burp_ca_path=args.burp_ca or "",
        blackbox_max_operations=getattr(args, "blackbox_max_operations", 3),
    )


def _run(args: argparse.Namespace) -> int:
    manager = JobManager()
    try:
        job = manager.create(_common_config(args))
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    while job.status not in {"completed", "failed"}:
        time.sleep(0.4)
    print(json.dumps(job.public(), ensure_ascii=False, indent=2))
    return 0 if job.status == "completed" else 1


def _web(args: argparse.Namespace) -> int:
    url = f"http://127.0.0.1:{args.port}"
    if not args.no_browser:
        webbrowser.open(url)
    # In a PyInstaller --windowed build stdout/stderr are None. Uvicorn's
    # default ColorFormatter calls sys.stdout.isatty(), so use the standard
    # logging defaults without Uvicorn's console-specific formatter.
    uvicorn.run(create_app(), host="127.0.0.1", port=args.port, log_config=None, access_log=False)
    return 0


def _demo(_: argparse.Namespace) -> int:
    base = Path(__file__).resolve().parent.parent / "examples"
    commands = [
        ("python", [sys.executable, "app.py"], base / "python_vulnerable"),
        ("javascript", ["node", "app.js"], base / "javascript_vulnerable"),
        ("java", ["java", "VulnerableApi"], base / "java_vulnerable"),
    ]
    java_dir = base / "java_vulnerable"
    if shutil.which("javac"):
        subprocess.run(["javac", "VulnerableApi.java"], cwd=java_dir, check=True)
    else:
        print("Skipping Java demo: javac was not found.")
        commands = commands[:-1]
    for name, command, cwd in commands:
        if not shutil.which(command[0]):
            print(f"Skipping {name} demo: {command[0]} was not found.")
            continue
        subprocess.Popen(command, cwd=cwd, creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        print(f"Started {name} demo from {cwd}")
    print("Python: http://127.0.0.1:9101/fetch?url=http://127.0.0.1:9199/marker")
    print("JavaScript: http://127.0.0.1:9102/file?name=../fixture-secret.txt")
    print("Java: http://127.0.0.1:9103/run?cmd=echo%20api_scan_marker_9f3a")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Authorized API security review workflow")
    sub = parser.add_subparsers(dest="command", required=True)
    web = sub.add_parser("web", help="Start the local web console")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--no-browser", action="store_true")
    web.set_defaults(handler=_web)
    run = sub.add_parser("run", help="Run a scan from the command line")
    run.add_argument("--source", required=True)
    run.set_defaults(scan_mode="source")
    run.add_argument("--target")
    run.add_argument("--allow", action="append", help="allowed host:port; repeatable")
    run.add_argument("--ai-provider", choices=["openai", "deepseek"], default="openai")
    run.add_argument("--model", help="OpenAI or DeepSeek model selected for the provider")
    run.add_argument("--confirm-authorized", action="store_true")
    run.add_argument("--use-burp", action="store_true", help="send controlled validation probes through Burp Proxy")
    run.add_argument("--burp-host", default="127.0.0.1")
    run.add_argument("--burp-port", default=8080, type=int)
    run.add_argument("--burp-ca")
    run.set_defaults(handler=_run)
    blackbox = sub.add_parser("openapi", help="Run an authorized, read-only OpenAPI black-box scan through Burp")
    blackbox.add_argument("--target", required=True, help="API base URL")
    blackbox.add_argument("--openapi-url", help="OpenAPI JSON/YAML URL; defaults to <target>/openapi.json")
    blackbox.add_argument("--allow", action="append", required=True, help="allowed host:port; repeatable")
    blackbox.add_argument("--ai-provider", choices=["openai", "deepseek"], default="openai")
    blackbox.add_argument("--model", help="OpenAI or DeepSeek model selected for the provider")
    blackbox.add_argument("--confirm-authorized", action="store_true", help="required before any OpenAPI request is sent")
    blackbox.add_argument("--burp-host", default="127.0.0.1")
    blackbox.add_argument("--burp-port", default=8080, type=int)
    blackbox.add_argument("--burp-ca", help="Burp CA PEM path for HTTPS")
    blackbox.add_argument("--blackbox-max-operations", default=3, type=int, help="1-10 documented GET/HEAD operations to capture")
    blackbox.set_defaults(handler=_run, scan_mode="openapi", use_burp=True, source="")
    demo = sub.add_parser("demo", help="Start deliberately vulnerable local demos")
    demo.set_defaults(handler=_demo)
    args = parser.parse_args()
    raise SystemExit(args.handler(args))
