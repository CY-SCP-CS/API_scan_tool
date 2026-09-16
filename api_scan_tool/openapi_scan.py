"""Conservative OpenAPI-driven black-box API surface review.

This module intentionally does not fuzz, guess paths, submit form bodies, or
send requests to undocumented routes.  It obtains one OpenAPI document through
Burp and, at most, performs read-only GET/HEAD captures for documented
operations that need no required parameters.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import requests
import yaml

from .models import Finding, RunConfig
from .redaction import redact
from .safety import SafetyError, safe_redirect
from .validation import check_burp

MAX_SPEC_BYTES = 1_000_000
READ_ONLY_METHODS = {"get", "head"}
_SSRF_NAMES = {"url", "uri", "callback", "webhook", "destination", "target", "endpoint", "host"}
_REDIRECT_NAMES = {"next", "redirect", "redirect_uri", "return", "return_url", "continue", "destination"}
_PATH_NAMES = {"file", "filename", "filepath", "path", "directory", "folder"}
_SENSITIVE_PATH_PARTS = {"admin", "internal", "debug", "manage", "management", "actuator"}


class OpenAPIScanError(RuntimeError):
    pass


def _spec_url(config: RunConfig) -> str:
    return config.openapi_url or urljoin(config.target_url.rstrip("/") + "/", "openapi.json")


def _proxy_settings(config: RunConfig) -> tuple[dict[str, str], bool | str]:
    proxy = f"http://{config.burp_host}:{config.burp_port}"
    return {"http": proxy, "https": proxy}, config.burp_ca_path or False


def _headers(config: RunConfig) -> dict[str, str]:
    return {**config.headers, "Accept": "application/json, application/yaml, text/yaml, */*;q=0.1", "X-API-Scan-Tool": "authorized-security-review"}


def _read_response(response: requests.Response) -> str:
    declared_length = response.headers.get("Content-Length")
    if declared_length and declared_length.isdigit() and int(declared_length) > MAX_SPEC_BYTES:
        raise OpenAPIScanError("OpenAPI document exceeds the 1 MB safety limit")
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=16_384):
        size += len(chunk)
        if size > MAX_SPEC_BYTES:
            raise OpenAPIScanError("OpenAPI document exceeds the 1 MB safety limit")
        chunks.append(chunk)
    return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")


def _load_document(config: RunConfig, emit: Callable[[str, str, dict], None]) -> tuple[dict[str, Any], str]:
    url = _spec_url(config)
    if not safe_redirect(url, config):
        raise SafetyError("OpenAPI document is outside the configured allowlist")
    proxies, verify = _proxy_settings(config)
    emit("openapi", "Fetching the OpenAPI document through Burp", {"url": url})
    try:
        response = requests.get(url, headers=_headers(config), proxies=proxies, verify=verify, allow_redirects=False, timeout=12, stream=True)
    except requests.RequestException as exc:
        raise OpenAPIScanError(f"Could not fetch the OpenAPI document through Burp: {exc}") from exc
    try:
        if not 200 <= response.status_code < 300:
            raise OpenAPIScanError(f"OpenAPI document returned HTTP {response.status_code}")
        raw = _read_response(response)
    finally:
        response.close()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        try:
            value = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise OpenAPIScanError("OpenAPI document is not valid JSON or YAML") from exc
    if not isinstance(value, dict) or not isinstance(value.get("paths"), dict) or not (value.get("openapi") or value.get("swagger")):
        raise OpenAPIScanError("The response is not an OpenAPI/Swagger document with a paths object")
    return value, url


def _operation_parameters(path_item: dict[str, Any], operation: dict[str, Any]) -> list[dict[str, Any]]:
    values = [*path_item.get("parameters", []), *operation.get("parameters", [])]
    return [item for item in values if isinstance(item, dict)]


def _parameter_name(parameter: dict[str, Any]) -> str:
    return str(parameter.get("name", "")).strip().lower()


def _candidate_kind(parameters: list[dict[str, Any]]) -> tuple[str, str] | None:
    names = {_parameter_name(item) for item in parameters}
    if names & _SSRF_NAMES:
        return "ssrf", "The OpenAPI contract exposes a URL-like input; server-side request handling needs review."
    if names & _REDIRECT_NAMES:
        return "redirect", "The OpenAPI contract exposes a redirect-like input; redirect validation needs review."
    if names & _PATH_NAMES:
        return "path_traversal", "The OpenAPI contract exposes a file/path-like input; path normalization needs review."
    return None


def _id(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()[:16]


def _context(spec_url: str, path: str, method: str, operation: dict[str, Any], parameters: list[dict[str, Any]]) -> str:
    evidence = {
        "document": spec_url,
        "path": path,
        "method": method.upper(),
        "summary": operation.get("summary", ""),
        "description": operation.get("description", ""),
        "parameters": [{"name": item.get("name"), "in": item.get("in"), "required": item.get("required", False)} for item in parameters],
    }
    return redact(json.dumps(evidence, ensure_ascii=False)[:4000])


def _capture_read_only_operation(config: RunConfig, spec_url: str, path: str, method: str, operation: dict[str, Any], parameters: list[dict[str, Any]], emit: Callable[[str, str, dict], None]) -> Finding:
    route = path if path.startswith("/") else "/" + path
    finding = Finding(
        id=_id("openapi-surface", method, route), rule_id="openapi.documented-read-operation",
        path=f"OpenAPI: {spec_url}", line=1, end_line=1,
        message="Documented read-only API operation captured through Burp", severity="INFO", language="openapi",
        vulnerability="api_surface", route=route, method=method.upper(), context=_context(spec_url, route, method, operation, parameters),
        review_required=False, active_validation_allowed=False,
    )
    if any(item.get("required") for item in parameters) or "{" in route or "}" in route:
        finding.validation = {"status": "skipped", "reason": "Documented operation requires parameters; the black-box scanner does not guess values"}
        return finding
    url = urljoin(config.target_url.rstrip("/") + "/", route.lstrip("/"))
    if not safe_redirect(url, config):
        finding.validation = {"status": "skipped", "reason": "Resolved operation is outside the configured allowlist"}
        return finding
    proxies, verify = _proxy_settings(config)
    emit("blackbox", f"Capturing documented {method.upper()} {route} through Burp", {"url": url, "method": method.upper()})
    try:
        response = requests.request(method.upper(), url, headers=_headers(config), proxies=proxies, verify=verify, allow_redirects=False, timeout=12)
        finding.validation = {
            "status": "captured",
            "via_burp": True,
            "request": {"method": method.upper(), "url": url},
            "response": {"status_code": response.status_code, "content_type": response.headers.get("Content-Type", ""), "content_length": response.headers.get("Content-Length", "")},
            "reason": "Read-only documented operation captured; response body was not stored.",
        }
    except requests.RequestException as exc:
        finding.validation = {"status": "inconclusive", "via_burp": True, "reason": str(exc)}
    return finding


def scan_openapi(config: RunConfig, emit: Callable[[str, str, dict], None]) -> list[Finding]:
    """Build contract candidates and capture a small number of safe documented reads."""
    check_burp(config)
    spec, spec_url = _load_document(config, emit)
    findings: list[Finding] = []
    captures: list[tuple[str, str, dict[str, Any], list[dict[str, Any]]]] = []
    global_security = bool(spec.get("security"))
    for raw_path, path_item in spec["paths"].items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/") or not isinstance(path_item, dict):
            continue
        for raw_method, operation in path_item.items():
            method = raw_method.lower()
            if method not in {"get", "head", "post", "put", "patch", "delete", "options"} or not isinstance(operation, dict):
                continue
            parameters = _operation_parameters(path_item, operation)
            context = _context(spec_url, raw_path, method, operation, parameters)
            candidate = _candidate_kind(parameters)
            active_allowed = method in READ_ONLY_METHODS
            if candidate:
                vulnerability, message = candidate
                findings.append(Finding(
                    id=_id("openapi-candidate", method, raw_path, vulnerability), rule_id=f"openapi.{vulnerability}-input",
                    path=f"OpenAPI: {spec_url}", line=1, end_line=1, message=message, severity="WARNING", language="openapi",
                    vulnerability=vulnerability, route=raw_path, method="GET", context=context,
                    active_validation_allowed=active_allowed,
                ))
            parts = {part.lower() for part in raw_path.split("/") if part}
            operation_security = operation.get("security", spec.get("security"))
            if parts & _SENSITIVE_PATH_PARTS and not operation_security and not global_security:
                findings.append(Finding(
                    id=_id("openapi-candidate", method, raw_path, "missing-auth"), rule_id="openapi.sensitive-operation-without-security",
                    path=f"OpenAPI: {spec_url}", line=1, end_line=1,
                    message="A sensitive documented operation does not declare an OpenAPI security requirement", severity="WARNING", language="openapi",
                    vulnerability="authorization", route=raw_path, method="GET", context=context,
                    active_validation_allowed=False,
                ))
            if method in READ_ONLY_METHODS:
                captures.append((raw_path, method, operation, parameters))
    max_captures = min(config.blackbox_max_operations, max(0, config.rate_limit_per_minute - 1))
    for raw_path, method, operation, parameters in captures[:max_captures]:
        findings.append(_capture_read_only_operation(config, spec_url, raw_path, method, operation, parameters, emit))
    emit("openapi", f"OpenAPI review produced {len(findings)} contract finding(s); captured {min(len(captures), max_captures)} documented read operation(s)", {"count": len(findings), "captures": min(len(captures), max_captures)})
    return findings
