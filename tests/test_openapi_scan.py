from typing import Any
from unittest.mock import patch

from api_scan_tool.models import RunConfig
from api_scan_tool.openapi_scan import scan_openapi


class FakeResponse:
    status_code = 200
    encoding = "utf-8"
    headers = {"Content-Length": "400", "Content-Type": "application/json"}

    def __init__(self, body: bytes = b"{}") -> None:
        self.body = body

    def iter_content(self, chunk_size: int = 16_384):
        yield self.body

    def close(self) -> None:
        return None


def test_openapi_scan_only_captures_documented_read_operations():
    document = b'''{
      "openapi": "3.0.0",
      "paths": {
        "/health": {"get": {"summary": "health"}},
        "/fetch": {"get": {"parameters": [{"name": "url", "in": "query"}]}},
        "/users": {"post": {"parameters": [{"name": "path", "in": "query"}]}},
        "/admin": {"get": {"summary": "admin"}}
      }
    }'''
    config = RunConfig(
        scan_mode="openapi", target_url="http://127.0.0.1:9101", allowlist=["127.0.0.1:9101"],
        use_burp=True, confirm_authorized=True, blackbox_max_operations=2,
    )
    requests_made: list[tuple[str, str]] = []

    def fake_get(url: str, **_: Any) -> FakeResponse:
        requests_made.append(("GET", url))
        return FakeResponse(document)

    def fake_request(method: str, url: str, **_: Any) -> FakeResponse:
        requests_made.append((method, url))
        return FakeResponse()

    with patch("api_scan_tool.openapi_scan.check_burp"), patch("api_scan_tool.openapi_scan.requests.get", side_effect=fake_get), patch("api_scan_tool.openapi_scan.requests.request", side_effect=fake_request):
        findings = scan_openapi(config, lambda *_: None)

    assert ("GET", "http://127.0.0.1:9101/openapi.json") in requests_made
    assert ("GET", "http://127.0.0.1:9101/health") in requests_made
    assert all(method == "GET" for method, _ in requests_made)
    assert any(item.vulnerability == "ssrf" for item in findings)
    assert any(item.vulnerability == "path_traversal" and not item.active_validation_allowed for item in findings)
    assert any(item.vulnerability == "authorization" for item in findings)
    captured = [item for item in findings if item.vulnerability == "api_surface"]
    assert captured and all(item.validation["status"] in {"captured", "skipped"} for item in captured)
    assert all("body_excerpt" not in item.validation.get("response", {}) for item in captured)
