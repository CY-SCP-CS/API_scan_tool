from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RunConfig:
    source_path: str
    target_url: str = ""
    languages: list[str] = field(default_factory=lambda: ["java", "python", "javascript"])
    allowlist: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    use_burp: bool = False
    burp_host: str = "127.0.0.1"
    burp_port: int = 8080
    burp_ca_path: str = ""
    rate_limit_per_minute: int = 12
    max_requests_per_finding: int = 2
    ai_provider: str = "openai"
    model: str = "gpt-5.6-terra"
    confirm_authorized: bool = False
    route_overrides: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def is_external(self) -> bool:
        from urllib.parse import urlparse

        host = (urlparse(self.target_url).hostname or "").lower()
        return host not in {"localhost", "127.0.0.1", "::1"}

    def public(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["headers"] = {key: "[configured]" for key in self.headers}
        return payload


@dataclass
class Finding:
    id: str
    rule_id: str
    path: str
    line: int
    end_line: int
    message: str
    severity: str
    language: str
    vulnerability: str
    route: str = "/"
    method: str = "GET"
    context: str = ""
    ai: dict[str, Any] = field(default_factory=dict)
    validation: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Job:
    id: str
    config: RunConfig
    status: str = "queued"
    stage: str = "queued"
    events: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    report_paths: dict[str, str] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "stage": self.stage,
            "error": self.error,
            "config": self.config.public(),
            "findings": [finding.public() for finding in self.findings],
            "report_paths": self.report_paths,
        }
