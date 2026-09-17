from pathlib import Path

from codecheck_backend import ReviewRequest, _collect_source, _prompt


def test_collect_source_redacts_and_prioritizes_files(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "SecurityConfig.java").write_text('String api_key = "secret-value";', encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("ignored", encoding="utf-8")
    files, summary = _collect_source(tmp_path)
    assert summary["indexed_files"] == 1
    assert files[0]["path"] == "src/SecurityConfig.java"
    assert "secret-value" not in files[0]["content"]


def test_prompt_requests_final_markdown(tmp_path: Path):
    request = ReviewRequest(source_path=str(tmp_path))
    prompt = _prompt(request, [{"path": "app.py", "content": "print('ok')"}], {"indexed_files": 1, "sent_files": 1, "truncated_files": 0, "context_chars": 12})
    assert "最终直接输出一份中文 Markdown 报告" in prompt
    assert "--- 文件：app.py ---" in prompt
