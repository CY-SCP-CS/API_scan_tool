import asyncio
from pathlib import Path

import httpx

from api_scan_tool.jobs import JobManager
from api_scan_tool.web import create_app


def test_health_is_local_and_does_not_expose_key(tmp_path: Path):
    app = create_app(JobManager(tmp_path))
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.get("/api/health")
    response = asyncio.run(request())
    assert response.status_code == 200
    assert "OPENAI_API_KEY" not in response.text
    assert "has_openai_api_key" in response.json()
    assert "has_deepseek_api_key" in response.json()


def test_external_request_without_confirmation_is_rejected(tmp_path: Path):
    app = create_app(JobManager(tmp_path))
    payload = {"source_path": ".", "target_url": "https://api.example.com", "allowlist": ["api.example.com:443"], "use_burp": True}
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.post("/api/jobs", json=payload)
    response = asyncio.run(request())
    assert response.status_code == 400
    assert "authorization" in response.json()["detail"]


def test_model_is_selected_from_supported_options(tmp_path: Path):
    app = create_app(JobManager(tmp_path))
    payload = {"source_path": ".", "model": "arbitrary-model-name"}
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.post("/api/jobs", json=payload)
    response = asyncio.run(request())
    assert response.status_code == 422


def test_deepseek_provider_accepts_only_deepseek_models(tmp_path: Path):
    app = create_app(JobManager(tmp_path))
    payload = {"source_path": ".", "ai_provider": "deepseek", "model": "gpt-5.6-terra"}
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.post("/api/jobs", json=payload)
    response = asyncio.run(request())
    assert response.status_code == 422


def test_completed_jobs_reload_from_disk(tmp_path: Path):
    runs = tmp_path / "persisted"; runs.mkdir()
    task = runs / "old-run"; task.mkdir()
    task.joinpath("job.json").write_text(
        '{"id":"old-run","status":"completed","stage":"completed","config":{"source_path":".","target_url":"","languages":["python"],"allowlist":[],"headers":{},"burp_host":"127.0.0.1","burp_port":8080,"burp_ca_path":"","rate_limit_per_minute":12,"max_requests_per_finding":2,"model":"","confirm_authorized":false,"route_overrides":{}},"findings":[],"events":[],"report_paths":{"html":"report.html"}}',
        encoding="utf-8",
    )
    manager = JobManager(runs)
    assert manager.get("old-run").status == "completed"
