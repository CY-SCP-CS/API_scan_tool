from __future__ import annotations

import socket
import time
from typing import Any, Callable
from urllib.parse import quote, urljoin, urlparse

import requests

from .models import Finding, RunConfig
from .safety import SafetyError, safe_redirect


class ValidationError(RuntimeError):
    pass


def check_burp(config: RunConfig) -> None:
    try:
        with socket.create_connection((config.burp_host, config.burp_port), timeout=2):
            return
    except OSError as exc:
        raise ValidationError(f"Burp Proxy is not reachable at {config.burp_host}:{config.burp_port}") from exc


def _probe(finding: Finding, external: bool) -> tuple[str, dict[str, str]]:
    marker = "api_scan_marker_9f3a"
    kind = finding.ai.get("poc_kind") or finding.vulnerability
    # External values intentionally only exercise parsing / validation paths.
    if kind == "path_traversal":
        return finding.route, {"name": "safe_probe.txt" if external else "../fixture-secret.txt"}
    if kind == "ssrf":
        return finding.route, {"url": "https://example.invalid/api-scan-marker" if external else "http://127.0.0.1:9199/marker"}
    if kind == "command_injection":
        return finding.route, {"cmd": "invalid-api-scan-marker" if external else "echo " + marker}
    if kind == "sql_injection":
        return finding.route, {"q": "api-scan-marker'"}
    if kind == "xss":
        return finding.route, {"q": "api-scan-marker"}
    if kind == "redirect":
        return finding.route, {"next": "/api-scan-marker"}
    return finding.route, {"probe": marker}


def validate(finding: Finding, config: RunConfig, emit: Callable[[str, str, dict], None]) -> dict[str, Any]:
    if not config.use_burp:
        return {"status": "skipped", "reason": "Burp verification is disabled; no HTTP probe was sent"}
    if not config.target_url:
        return {"status": "skipped", "reason": "No target URL configured"}
    check_burp(config)
    path, params = _probe(finding, config.is_external)
    url = urljoin(config.target_url.rstrip("/") + "/", path.lstrip("/"))
    if not safe_redirect(url, config):
        raise SafetyError("resolved validation route is outside the configured allowlist")
    proxy = f"http://{config.burp_host}:{config.burp_port}"
    verify: bool | str = config.burp_ca_path if config.burp_ca_path else False
    headers = {**config.headers, "X-API-Scan-Tool": "authorized-security-review"}
    emit("validation", f"Sending controlled {finding.vulnerability} probe through Burp", {"finding_id": finding.id, "url": url})
    try:
        response = requests.request(
            finding.method if finding.method in {"GET", "POST"} else "GET",
            url,
            params=params if finding.method != "POST" else None,
            json=params if finding.method == "POST" else None,
            headers=headers,
            proxies={"http": proxy, "https": proxy},
            verify=verify,
            allow_redirects=False,
            timeout=12,
        )
    except requests.RequestException as exc:
        return {"status": "inconclusive", "reason": str(exc), "via_burp": True}
    body = response.text[:2000]
    confirmed = ("api_scan_marker_9f3a" in body or "fixture-secret" in body) and not config.is_external
    return {
        "status": "confirmed" if confirmed else "captured",
        "via_burp": True,
        "request": {"method": finding.method, "url": url, "params": params},
        "response": {"status_code": response.status_code, "body_excerpt": body},
        "reason": "Local controlled marker observed" if confirmed else "Request and response captured by Burp; manual evidence review may be required",
    }
