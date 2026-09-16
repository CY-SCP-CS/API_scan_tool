from pathlib import Path

from api_scan_tool.models import Finding, Job, RunConfig
from api_scan_tool.reports import write_reports


def test_writes_all_report_types(tmp_path: Path):
    job = Job(id="test-run", config=RunConfig(source_path="."), findings=[Finding("id", "rule", "app.py", 2, 2, "message", "ERROR", "python", "ssrf")])
    paths = write_reports(job, tmp_path)
    assert set(paths) == {"json", "html", "sarif"}
    assert all(Path(value).is_file() for value in paths.values())
