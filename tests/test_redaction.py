from api_scan_tool.redaction import redact


def test_redacts_common_secrets():
    output = redact('API_KEY="very-secret-value"\nurl="postgres://user:password@db/app"\nsk-abcdefghijklmnopqrst')
    assert "very-secret-value" not in output
    assert "postgres://" not in output
    assert "sk-abcdefghijklmnopqrst" not in output
