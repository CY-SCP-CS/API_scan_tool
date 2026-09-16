from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ai_review import review
from .engine import scan
from .models import Finding, Job, RunConfig
from .openapi_scan import scan_openapi
from .reports import write_reports
from .safety import validate_config
from .validation import validate


class JobManager:
    def __init__(self, run_root: Path | None = None) -> None:
        self.run_root = run_root or Path.cwd() / "runs"
        self.run_root.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._load_existing()

    def _load_existing(self) -> None:
        """Restore completed jobs so reports remain accessible after a restart.

        Header values are never persisted because Job.public() redacts them before
        this file is written.
        """
        for path in self.run_root.glob("*/job.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                config = RunConfig(**data["config"])
                findings = [Finding(**item) for item in data.get("findings", [])]
                job = Job(
                    id=data["id"], config=config, status=data.get("status", "failed"), stage=data.get("stage", "completed"),
                    events=data.get("events", []), findings=findings, error=data.get("error", ""), report_paths=data.get("report_paths", {}),
                )
                self._jobs[job.id] = job
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue

    def create(self, config: RunConfig) -> Job:
        validate_config(config)
        job = Job(id=uuid.uuid4().hex[:12], config=config)
        with self._lock:
            self._jobs[job.id] = job
        self._emit(job, "queued", "Task queued", {})
        threading.Thread(target=self._run, args=(job,), name=f"scan-{job.id}", daemon=True).start()
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda item: item.events[0]["time"] if item.events else "", reverse=True)

    def _emit(self, job: Job, stage: str, message: str, data: dict[str, Any]) -> None:
        event = {"time": datetime.now(timezone.utc).isoformat(), "stage": stage, "message": message, "data": data}
        with self._lock:
            job.stage = stage
            job.events.append(event)

    def _run(self, job: Job) -> None:
        job.status = "running"
        try:
            scanner = scan_openapi if job.config.scan_mode == "openapi" else scan
            findings = scanner(job.config, lambda stage, message, data: self._emit(job, stage, message, data))
            job.findings = findings
            for finding in job.findings:
                if not finding.review_required:
                    finding.ai = {
                        "confirmed": False,
                        "confidence": 0,
                        "summary": "Documented API surface captured with a read-only request; this is not a vulnerability conclusion.",
                        "impact": "No active vulnerability payload was sent.",
                        "recommended_fix": "Review the endpoint's authorization and input validation controls as appropriate.",
                        "poc_kind": "none",
                    }
                    continue
                finding.ai = review(finding, job.config, lambda stage, message, data: self._emit(job, stage, message, data))
            if job.config.use_burp:
                self._emit(job, "validation", "Checking Burp and validating reviewed findings", {})
                for finding in job.findings:
                    if not finding.active_validation_allowed:
                        finding.validation = {"status": "skipped", "reason": "This OpenAPI operation is not GET/HEAD; no active request will be sent"}
                        continue
                    if not finding.ai.get("confirmed", False):
                        finding.validation = {"status": "skipped", "reason": "AI marked this finding as unlikely"}
                        continue
                    finding.validation = validate(finding, job.config, lambda stage, message, data: self._emit(job, stage, message, data))
            else:
                self._emit(job, "validation", "Burp verification is disabled; no HTTP probes will be sent", {})
                for finding in job.findings:
                    finding.validation = {"status": "skipped", "reason": "Burp verification is disabled; no HTTP probe was sent"}
            job.status = "completed"
            self._emit(job, "report", "Writing JSON, HTML and SARIF reports", {})
        except Exception as exc:  # Keep the job and its partial evidence available.
            job.status = "failed"
            job.error = str(exc)
            self._emit(job, "failed", str(exc), {})
        finally:
            job.report_paths = write_reports(job, self.run_root)
            self._emit(job, "completed" if job.status == "completed" else "failed", f"Task {job.status}", {})
            self._persist(job)

    def _persist(self, job: Job) -> None:
        directory = self.run_root / job.id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "job.json").write_text(json.dumps({**job.public(), "events": job.events}, ensure_ascii=False, indent=2), encoding="utf-8")
