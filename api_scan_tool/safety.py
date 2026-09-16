from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from .models import RunConfig


class SafetyError(ValueError):
    pass


def _authority(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SafetyError("target_url must be an absolute http(s) URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.hostname.lower()}:{port}"


def validate_config(config: RunConfig) -> None:
    if config.scan_mode not in {"source", "openapi"}:
        raise SafetyError("scan_mode must be source or openapi")
    if config.scan_mode == "source" and not config.source_path:
        raise SafetyError("source_path is required")
    # A target is inert until the user explicitly enables Burp validation.
    # Static analysis and AI review work without a target or network access.
    if config.use_burp:
        if not config.target_url:
            raise SafetyError("target_url is required when Burp validation is enabled")
        authority = _authority(config.target_url)
        if authority not in {entry.lower() for entry in config.allowlist}:
            raise SafetyError(f"target {authority} is not in the allowlist")
        if config.is_external and not config.confirm_authorized:
            raise SafetyError("external validation requires explicit authorization confirmation")
    if config.scan_mode == "openapi":
        if not config.target_url:
            raise SafetyError("target_url is required for OpenAPI black-box scanning")
        if not config.use_burp:
            raise SafetyError("OpenAPI black-box scanning requires Burp to be enabled")
        if not config.confirm_authorized:
            raise SafetyError("OpenAPI black-box scanning requires explicit authorization confirmation")
        if urlparse(config.target_url).scheme == "https" and not config.burp_ca_path:
            raise SafetyError("HTTPS OpenAPI black-box scanning requires a trusted Burp CA PEM path")
        if config.openapi_url:
            authority = _authority(config.openapi_url)
            if authority not in {entry.lower() for entry in config.allowlist}:
                raise SafetyError(f"OpenAPI document {authority} is not in the allowlist")
    if config.rate_limit_per_minute < 1 or config.rate_limit_per_minute > 60:
        raise SafetyError("rate_limit_per_minute must be between 1 and 60")
    if config.max_requests_per_finding < 1 or config.max_requests_per_finding > 5:
        raise SafetyError("max_requests_per_finding must be between 1 and 5")
    if config.blackbox_max_operations < 1 or config.blackbox_max_operations > 10:
        raise SafetyError("blackbox_max_operations must be between 1 and 10")


def safe_redirect(url: str, config: RunConfig) -> bool:
    """Allow redirects only to the configured scope; never resolve unknown hosts."""
    try:
        authority = _authority(url)
    except SafetyError:
        return False
    return authority in {entry.lower() for entry in config.allowlist}


def is_private_or_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
    except ValueError:
        try:
            addresses = socket.gethostbyname_ex(host)[2]
        except socket.gaierror:
            return True
        return any(ipaddress.ip_address(address).is_private or ipaddress.ip_address(address).is_loopback for address in addresses)
