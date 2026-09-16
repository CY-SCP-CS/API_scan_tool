from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from .jobs import JobManager
from .models import RunConfig
from .runtime import load_runtime_env
from .safety import SafetyError

load_runtime_env()
PACKAGE = Path(__file__).resolve().parent
manager = JobManager()


class RunPayload(BaseModel):
    source_path: str = ""
    scan_mode: Literal["source", "openapi"] = "source"
    target_url: str = ""
    openapi_url: str = ""
    languages: list[str] = Field(default_factory=lambda: ["java", "python", "javascript"])
    allowlist: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    use_burp: bool = False
    burp_host: str = "127.0.0.1"
    burp_port: int = 8080
    burp_ca_path: str = ""
    rate_limit_per_minute: int = 12
    max_requests_per_finding: int = 2
    blackbox_max_operations: int = 3
    ai_provider: Literal["openai", "deepseek"] = "openai"
    model: Literal["gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.6-sol", "deepseek-flash", "deepseek-v4-pro"] = "gpt-5.6-terra"
    confirm_authorized: bool = False
    route_overrides: dict[str, dict[str, str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def provider_matches_model(self) -> "RunPayload":
        allowed = {
            "openai": {"gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.6-sol"},
            "deepseek": {"deepseek-flash", "deepseek-v4-pro"},
        }
        if self.model not in allowed[self.ai_provider]:
            raise ValueError("the selected model does not belong to the selected AI provider")
        if self.scan_mode == "source" and not self.source_path.strip():
            raise ValueError("source_path is required for source scanning")
        return self

    def config(self) -> RunConfig:
        return RunConfig(**self.model_dump())


def create_app(job_manager: JobManager | None = None) -> FastAPI:
    app = FastAPI(title="API Scan Tool", docs_url=None, redoc_url=None)
    active_manager = job_manager or manager
    app.mount("/static", StaticFiles(directory=PACKAGE / "static"), name="static")

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return (PACKAGE / "templates" / "index.html").read_text(encoding="utf-8")

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "host": "127.0.0.1",
            "has_openai_api_key": bool(os.getenv("OPENAI_API_KEY")),
            "has_deepseek_api_key": bool(os.getenv("DEEPSEEK_API_KEY")),
        }

    @app.post("/api/jobs", status_code=202)
    def create_job(payload: RunPayload) -> dict[str, Any]:
        try:
            job = active_manager.create(payload.config())
        except SafetyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return job.public()

    @app.get("/api/jobs")
    def list_jobs() -> list[dict[str, Any]]:
        return [job.public() for job in active_manager.list()]

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, Any]:
        job = active_manager.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Unknown task")
        return {**job.public(), "events": job.events}

    @app.get("/api/jobs/{job_id}/events")
    async def events(job_id: str) -> StreamingResponse:
        async def stream():
            index = 0
            while True:
                job = active_manager.get(job_id)
                if not job:
                    yield "event: error\ndata: {\"message\":\"Unknown task\"}\n\n"
                    return
                while index < len(job.events):
                    yield f"data: {json.dumps(job.events[index], ensure_ascii=False)}\n\n"
                    index += 1
                if job.status in {"completed", "failed"}:
                    yield f"event: done\ndata: {json.dumps(job.public(), ensure_ascii=False)}\n\n"
                    return
                await asyncio.sleep(0.5)
        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    @app.get("/api/jobs/{job_id}/reports/{kind}")
    def report(job_id: str, kind: str) -> FileResponse:
        job = active_manager.get(job_id)
        if not job or kind not in job.report_paths:
            raise HTTPException(status_code=404, detail="Report is not available")
        return FileResponse(job.report_paths[kind], filename=f"{job_id}.{ 'sarif' if kind == 'sarif' else kind }")

    return app


app = create_app()
