"""Local backend for the source-only AI code review console."""
from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator

from api_scan_tool.runtime import load_runtime_env
from api_scan_tool.redaction import redact

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "codeCheck" / "codeCheck"
RUN_ROOT = Path.cwd() / "runs" / "code-review"
PROMPT_PATH = WEB_ROOT / "未登录接口访问代码审查提示词.md"
TEXT_EXTENSIONS = {".java", ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".php", ".cs", ".xml", ".yml", ".yaml", ".properties", ".json", ".conf", ".ini", ".gradle", ".sql", ".html", ".vue"}
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", "venv", ".venv", "__pycache__", ".idea", ".vscode"}
IMPORTANT = ("pom.xml", "build.gradle", "package.json", "requirements.txt", "settings.py", "urls.py", "application.", "security", "auth", "filter", "interceptor", "middleware", "controller", "router", "route", "config", "nginx")
MAX_FILES = 80
MAX_FILE_CHARS = 24_000
MAX_CONTEXT_CHARS = 280_000


class ReviewRequest(BaseModel):
    source_path: str
    ai_provider: Literal["openai", "deepseek"] = "openai"
    model: Literal["gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.6-sol", "deepseek-flash", "deepseek-v4-pro"] = "gpt-5.6-terra"

    @field_validator("source_path")
    @classmethod
    def source_must_be_directory(cls, value: str) -> str:
        path = Path(value).expanduser()
        if not path.is_dir():
            raise ValueError("源码目录不存在或无法访问")
        return str(path.resolve())

    @model_validator(mode="after")
    def model_belongs_to_provider(self) -> "ReviewRequest":
        allowed = {
            "openai": {"gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.6-sol"},
            "deepseek": {"deepseek-flash", "deepseek-v4-pro"},
        }
        if self.model not in allowed[self.ai_provider]:
            raise ValueError("所选模型不属于当前 AI 提供商")
        return self


@dataclass
class ReviewJob:
    id: str
    request: ReviewRequest
    status: str = "queued"
    events: list[str] = field(default_factory=list)
    report_markdown: str = ""
    error: str = ""

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "status": self.status, "events": self.events, "report_markdown": self.report_markdown, "error": self.error}


def _is_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name in {"Dockerfile", "Makefile", "pom.xml"}


def _collect_source(root: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    indexed: list[Path] = []
    for path in root.rglob("*"):
        if len(indexed) >= 4_000:
            break
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(root).parts) or not _is_text(path):
            continue
        indexed.append(path)
    indexed.sort(key=lambda path: (not any(key in path.name.lower() or key in str(path.relative_to(root)).lower() for key in IMPORTANT), len(path.parts), str(path)))
    selected: list[dict[str, str]] = []
    used = 0
    truncated = 0
    for path in indexed[:MAX_FILES]:
        try:
            text = redact(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if len(text) > MAX_FILE_CHARS:
            text = text[:MAX_FILE_CHARS] + "\n[文件其余内容未发送]"
            truncated += 1
        block = f"\n\n--- 文件：{path.relative_to(root).as_posix()} ---\n{text}"
        if used + len(block) > MAX_CONTEXT_CHARS:
            break
        selected.append({"path": path.relative_to(root).as_posix(), "content": text})
        used += len(block)
    summary = {"indexed_files": len(indexed), "sent_files": len(selected), "truncated_files": truncated, "context_chars": used}
    return selected, summary


def _prompt(request: ReviewRequest, files: list[dict[str, str]], summary: dict[str, Any]) -> str:
    rules = PROMPT_PATH.read_text(encoding="utf-8") if PROMPT_PATH.is_file() else "审查未登录即可访问受限接口。"
    snippets = "".join(f"\n\n--- 文件：{item['path']} ---\n{item['content']}" for item in files)
    return f"""{rules}

## 本次后端提供的真实源码范围

- 源码目录：{request.source_path}
- 已建立索引文件：{summary['indexed_files']}
- 已发送给模型的文件：{summary['sent_files']}
- 截断文件：{summary['truncated_files']}

仅根据下方真实代码和配置作出结论。不要编造未提供的文件、路由、行号、运行验证或影响。若认证链或部署条件无法追踪，放入 D 节覆盖缺口及待确认事项。

最终直接输出一份中文 Markdown 报告，严格按提示词中的 A. 审查摘要、B. 问题接口清单、C. 问题明细、D. 覆盖缺口及待确认事项组织；不要输出推理过程、寒暄或代码围栏。没有证据充分的问题时，不要生成空问题表。

## 源码内容
{snippets}"""


def _call_model(request: ReviewRequest, prompt: str) -> str:
    load_runtime_env()
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("缺少 OpenAI SDK；请安装 requirements.txt") from exc
    if request.ai_provider == "deepseek":
        key = os.getenv("DEEPSEEK_API_KEY")
        if not key:
            raise RuntimeError("未配置 DEEPSEEK_API_KEY；请在 EXE 同目录的 .env 填写")
        response = OpenAI(api_key=key, base_url="https://api.deepseek.com").chat.completions.create(
            model=request.model, max_tokens=8_000,
            messages=[{"role": "system", "content": "你是严格、保守的应用安全代码审查专家。仅输出最终 Markdown 报告。"}, {"role": "user", "content": prompt}],
        )
        content = response.choices[0].message.content if response.choices else ""
    else:
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("未配置 OPENAI_API_KEY；请在 EXE 同目录的 .env 填写")
        response = OpenAI(api_key=key).responses.create(
            model=request.model, store=False,
            instructions="你是严格、保守的应用安全代码审查专家。仅输出最终 Markdown 报告。",
            input=prompt,
        )
        content = response.output_text
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("AI 没有返回可用的 Markdown 报告")
    return content.strip()


class ReviewManager:
    def __init__(self) -> None:
        self.jobs: dict[str, ReviewJob] = {}
        self.lock = threading.Lock()
        RUN_ROOT.mkdir(parents=True, exist_ok=True)

    def create(self, request: ReviewRequest) -> ReviewJob:
        job = ReviewJob(id=uuid.uuid4().hex[:12], request=request)
        with self.lock:
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True, name=f"code-review-{job.id}").start()
        return job

    def get(self, job_id: str) -> ReviewJob | None:
        with self.lock:
            return self.jobs.get(job_id)

    def _event(self, job: ReviewJob, message: str) -> None:
        with self.lock:
            job.events.append(message)

    def _run(self, job: ReviewJob) -> None:
        job.status = "running"
        try:
            self._event(job, "正在索引并筛选源码文件…")
            files, summary = _collect_source(Path(job.request.source_path))
            if not files:
                raise RuntimeError("源码目录中没有可审查的文本源码或配置文件")
            self._event(job, f"已索引 {summary['indexed_files']} 个文件，向 AI 提供 {summary['sent_files']} 个重点文件。")
            self._event(job, f"正在使用 {job.request.ai_provider} 生成最终 Markdown 报告…")
            job.report_markdown = _call_model(job.request, _prompt(job.request, files, summary))
            job.status = "completed"
            self._event(job, "审查完成，最终 Markdown 报告已生成。")
            directory = RUN_ROOT / job.id
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "report.md").write_text(job.report_markdown, encoding="utf-8")
            (directory / "job.json").write_text(json.dumps({"id": job.id, "status": job.status, "source_path": job.request.source_path, "events": job.events, "created_at": datetime.now(timezone.utc).isoformat()}, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:
            job.status = "failed"
            job.error = str(exc)
            self._event(job, f"审查失败：{job.error}")


manager = ReviewManager()


def create_app() -> FastAPI:
    app = FastAPI(title="Code Check", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=WEB_ROOT), name="static")

    @app.get("/")
    def home() -> FileResponse:
        return FileResponse(WEB_ROOT / "index.html")

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        load_runtime_env()
        return {"status": "ok", "has_openai_api_key": bool(os.getenv("OPENAI_API_KEY")), "has_deepseek_api_key": bool(os.getenv("DEEPSEEK_API_KEY"))}

    @app.post("/api/reviews", status_code=202)
    def create_review(request: ReviewRequest) -> dict[str, Any]:
        return manager.create(request).public()

    @app.get("/api/reviews/{job_id}")
    def get_review(job_id: str) -> dict[str, Any]:
        job = manager.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="未知审查任务")
        return job.public()

    @app.get("/api/reviews/{job_id}/report")
    def report(job_id: str) -> FileResponse:
        path = RUN_ROOT / job_id / "report.md"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="报告尚未生成")
        return FileResponse(path, filename=f"code-review-{job_id}.md", media_type="text/markdown")

    return app


app = create_app()
