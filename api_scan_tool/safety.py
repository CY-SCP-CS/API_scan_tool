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
    if not config.source_path:
        raise SafetyError("source_path is required")
    # A target is inert until the user explicitly enables Burp validation.
    # Static analysis and AI review work without a target or network access.
    if config.target_url and config.use_burp:
        authority = _authority(config.target_url)
        if authority not in {entry.lower() for entry in config.allowlist}:
            raise SafetyError(f"target {authority} is not in the allowlist")
        if config.is_external and not config.confirm_authorized:
            raise SafetyError("external validation requires explicit authorization confirmation")
    if config.rate_limit_per_minute < 1 or config.rate_limit_per_minute > 60:
        raise SafetyError("rate_limit_per_minute must be between 1 and 60")
    if config.max_requests_per_finding < 1 or config.max_requests_per_finding > 5:
        raise SafetyError("max_requests_per_finding must be between 1 and 5")


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
