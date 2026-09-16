from api_scan_tool.models import Finding, RunConfig
from api_scan_tool.validation import validate


def test_burp_disabled_never_opens_a_network_connection():
    config = RunConfig(source_path=".", target_url="https://not-in-the-allowlist.invalid", use_burp=False)
    finding = Finding("id", "rule", "app.py", 1, 1, "message", "ERROR", "python", "ssrf")
    result = validate(finding, config, lambda *_: None)
    assert result["status"] == "skipped"
    assert "no HTTP probe" in result["reason"]
