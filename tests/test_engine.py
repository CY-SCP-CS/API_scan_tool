import json
from pathlib import Path
from unittest.mock import patch

import pytest

from api_scan_tool.engine import ScanError, scan
from api_scan_tool.models import RunConfig


class Result:
    returncode = 0
    stderr = ""
    stdout = ""


def test_scan_normalizes_semgrep_result_and_redacts_context(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text('API_KEY="secret-value"\nimport urllib.request\nurllib.request.urlopen(url)\n', encoding="utf-8")
    result = Result()
    result.stdout = json.dumps({"results": [{
        "check_id": "api.python.urlopen", "path": str(source),
        "start": {"line": 3}, "end": {"line": 3},
        "extra": {"message": "SSRF", "severity": "ERROR", "metadata": {"vulnerability": "ssrf", "route": "/fetch", "method": "GET"}},
    }]})
    config = RunConfig(source_path=str(tmp_path), languages=["python"])
    with patch("api_scan_tool.engine._semgrep_path", return_value="semgrep"), patch("api_scan_tool.engine.subprocess.run", return_value=result):
        findings = scan(config, lambda *_: None)
    assert len(findings) == 1
    assert findings[0].vulnerability == "ssrf"
    assert "secret-value" not in findings[0].context
    assert findings[0].route == "/fetch"


def test_scan_explains_windows_certificate_store_error(tmp_path: Path):
    result = Result()
    result.returncode = 2
    result.stderr = "CertOpenSystemStore returned NULL\n" + ("stack line\n" * 300)
    config = RunConfig(source_path=str(tmp_path), languages=["python"])
    with patch("api_scan_tool.engine._semgrep_path", return_value="semgrep"), patch("api_scan_tool.engine.subprocess.run", return_value=result):
        with pytest.raises(ScanError, match="certificate store"):
            scan(config, lambda *_: None)
