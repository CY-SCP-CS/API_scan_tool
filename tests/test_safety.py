import pytest

from api_scan_tool.models import RunConfig
from api_scan_tool.safety import SafetyError, safe_redirect, validate_config


def test_external_target_requires_explicit_authorization():
    config = RunConfig(source_path=".", target_url="https://api.example.com", allowlist=["api.example.com:443"], use_burp=True)
    with pytest.raises(SafetyError, match="authorization"):
        validate_config(config)


def test_allowlist_rejects_unlisted_target():
    config = RunConfig(source_path=".", target_url="http://127.0.0.1:9000", allowlist=["127.0.0.1:9001"], use_burp=True)
    with pytest.raises(SafetyError, match="allowlist"):
        validate_config(config)


def test_redirect_stays_in_allowlist():
    config = RunConfig(source_path=".", allowlist=["api.example.com:443"])
    assert safe_redirect("https://api.example.com/v1", config)
    assert not safe_redirect("https://other.example.com/v1", config)
