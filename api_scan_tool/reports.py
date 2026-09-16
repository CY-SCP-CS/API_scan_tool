from __future__ import annotations

import html
import json
from pathlib import Path

from .models import Job


def write_reports(job: Job, root: Path) -> dict[str, str]:
    directory = root / job.id
    directory.mkdir(parents=True, exist_ok=True)
    payload = job.public()
    json_path = directory / "report.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "API Scan Tool"}}, "results": [
            {"ruleId": finding.rule_id, "level": "error" if finding.severity == "ERROR" else "warning",
             "message": {"text": finding.message}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.path}, "region": {"startLine": finding.line}}}],
             "properties": {"ai": finding.ai, "validation": finding.validation}}
            for finding in job.findings
        ]}]}
    sarif_path = directory / "report.sarif"
    sarif_path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    rows = "".join(
        f"<tr><td>{html.escape(finding.severity)}</td><td>{html.escape(finding.vulnerability)}</td><td>{html.escape(finding.path)}:{finding.line}</td><td>{html.escape(finding.validation.get('status', 'not validated'))}</td><td>{html.escape(finding.ai.get('summary', ''))}</td></tr>"
        for finding in job.findings
    )
    html_path = directory / "report.html"
    html_path.write_text(f"""<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>API Scan {job.id}</title><style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}th,td{{padding:.6rem;border-bottom:1px solid #ddd;text-align:left}}</style><h1>API Scan Report</h1><p>任务：{html.escape(job.id)}；状态：{html.escape(job.status)}</p><table><thead><tr><th>严重度</th><th>类别</th><th>位置</th><th>验证</th><th>AI 摘要</th></tr></thead><tbody>{rows}</tbody></table></html>""", encoding="utf-8")
    return {"json": str(json_path), "sarif": str(sarif_path), "html": str(html_path)}
