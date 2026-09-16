from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

from .models import Finding, RunConfig
from .redaction import redact

ROOT = Path(__file__).resolve().parent
RULES = ROOT / "rules" / "api-security.yml"


class ScanError(RuntimeError):
    pass


def _language_for(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return {".java": "java", ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript"}.get(suffix, "unknown")


def _semgrep_path() -> str | None:
    """Prefer the executable installed alongside the interpreter running this app."""
    if getattr(sys, "frozen", False):
        executable_dir = Path(sys.executable).resolve().parent
        resource_dir = Path(getattr(sys, "_MEIPASS", executable_dir))
        for candidate in (
            executable_dir / "semgrep" / "semgrep-runner.exe",
            resource_dir / "semgrep" / "semgrep-runner.exe",
            executable_dir / "semgrep-runner.exe",
        ):
            if candidate.is_file():
                return str(candidate)
    scripts = Path(sys.executable).resolve().parent
    candidates = [scripts / "semgrep.exe", scripts / "semgrep"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return shutil.which("semgrep")


def _context(path: Path, start: int, end: int, radius: int = 6) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    first = max(0, start - radius - 1)
    last = min(len(lines), end + radius)
    return redact("\n".join(f"{index + 1}: {line}" for index, line in enumerate(lines[first:last], first)))


def scan(config: RunConfig, emit: Callable[[str, str, dict], None]) -> list[Finding]:
    source = Path(config.source_path).resolve()
    if not source.is_dir():
        raise ScanError(f"source directory does not exist: {source}")
    semgrep = _semgrep_path()
    if not semgrep:
        raise ScanError("Semgrep was not found. Install requirements.txt in the active virtual environment.")
    command = [semgrep, "scan", "--config", str(RULES), "--json", "--quiet", str(source)]
    emit("semgrep", "Running local Semgrep rules", {"command": "semgrep scan --config api-security.yml"})
    process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    # Semgrep returns 1 when findings exist.
    if process.returncode not in {0, 1}:
        raw_detail = (process.stderr or process.stdout).strip()
        detail = raw_detail[-1200:]
        if "CertOpenSystemStore" in raw_detail:
            detail = "Semgrep could not read the Windows certificate store. Repair/update Windows root certificates or run in an environment where the certificate store is available. " + detail
        raise ScanError(f"Semgrep failed ({process.returncode}): {detail}")
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise ScanError(f"Semgrep did not return JSON: {process.stdout[-500:]}") from exc
    findings: list[Finding] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        path = Path(result["path"])
        start = result["start"]["line"]
        end = result["end"]["line"]
        identifier = hashlib.sha256(f"{result['check_id']}:{path}:{start}".encode()).hexdigest()[:16]
        override = config.route_overrides.get(result["check_id"], {})
        language = _language_for(str(path))
        if language not in config.languages:
            continue
        findings.append(Finding(
            id=identifier,
            rule_id=result["check_id"],
            path=str(path),
            line=start,
            end_line=end,
            message=extra.get("message", result["check_id"]),
            severity=extra.get("severity", "WARNING").upper(),
            language=language,
            vulnerability=metadata.get("vulnerability", "unknown"),
            route=override.get("route", metadata.get("route", "/")),
            method=override.get("method", metadata.get("method", "GET")).upper(),
            context=_context(path, start, end),
        ))
    emit("semgrep", f"Semgrep found {len(findings)} potential issue(s)", {"count": len(findings)})
    return findings
