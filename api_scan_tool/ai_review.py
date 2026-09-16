from __future__ import annotations

import json
import os
from typing import Any, Callable

from .models import Finding, RunConfig
from .runtime import load_runtime_env

REVIEW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["confirmed", "confidence", "summary", "impact", "recommended_fix", "poc_kind"],
    "properties": {
        "confirmed": {"type": "boolean"},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "summary": {"type": "string"},
        "impact": {"type": "string"},
        "recommended_fix": {"type": "string"},
        "poc_kind": {"type": "string", "enum": ["sql_injection", "ssrf", "path_traversal", "command_injection", "xss", "redirect", "none"]},
    },
}


def _prompt(finding: Finding) -> dict[str, str]:
    return {
        "rule_id": finding.rule_id,
        "language": finding.language,
        "static_message": finding.message,
        "candidate_vulnerability": finding.vulnerability,
        "source_context": finding.context,
        "instructions": "Review only this code evidence. Do not propose exploit chains or destructive payloads. Return a concise security assessment.",
    }


def _validate_assessment(value: Any, provider: str) -> dict[str, Any]:
    required = REVIEW_SCHEMA["required"]
    if not isinstance(value, dict) or not set(required).issubset(value):
        raise RuntimeError(f"{provider} returned an invalid structured review")
    if not isinstance(value["confirmed"], bool) or not isinstance(value["confidence"], int):
        raise RuntimeError(f"{provider} returned an invalid structured review")
    if not 0 <= value["confidence"] <= 100 or value["poc_kind"] not in REVIEW_SCHEMA["properties"]["poc_kind"]["enum"]:
        raise RuntimeError(f"{provider} returned an invalid structured review")
    if any(not isinstance(value[field], str) for field in ("summary", "impact", "recommended_fix", "poc_kind")):
        raise RuntimeError(f"{provider} returned an invalid structured review")
    # DeepSeek JSON mode may legitimately include provider-specific metadata.
    # Persist only the review contract fields; no unexpected provider output is
    # copied into the report.
    return {field: value[field] for field in required}


def _normalise_deepseek_assessment(value: dict[str, Any], candidate: str) -> dict[str, Any]:
    """Accept safe, common DeepSeek field aliases before contract validation."""
    # Some compatible endpoints wrap the actual review in a named object.
    for wrapper in ("review", "assessment", "result", "data"):
        if isinstance(value.get(wrapper), dict):
            value = value[wrapper]
    aliases = {
        "is_confirmed": "confirmed",
        "is_vulnerable": "confirmed",
        "vulnerable": "confirmed",
        "recommendation": "recommended_fix",
        "fix": "recommended_fix",
        "recommend_fix": "recommended_fix",
        "recommendedfix": "recommended_fix",
        "poc_type": "poc_kind",
        "vulnerability_type": "poc_kind",
    }
    normalised = dict(value)
    compact = {"".join(char for char in key.lower() if char.isalnum()): item for key, item in value.items() if isinstance(key, str)}
    for source, target in aliases.items():
        source_key = "".join(char for char in source.lower() if char.isalnum())
        if target not in normalised and source_key in compact:
            normalised[target] = compact[source_key]
    if "confirmed" not in normalised and isinstance(compact.get("verdict"), str):
        normalised["confirmed"] = compact["verdict"].lower() in {"true", "yes", "confirmed", "vulnerable"}
    if isinstance(normalised.get("confirmed"), str):
        text = normalised["confirmed"].strip().lower()
        if text in {"true", "yes", "confirmed", "vulnerable", "是", "存在"}:
            normalised["confirmed"] = True
        elif text in {"false", "no", "unconfirmed", "not_vulnerable", "否", "不存在"}:
            normalised["confirmed"] = False
    if isinstance(normalised.get("confidence"), str):
        text = normalised["confidence"].strip().rstrip("%")
        try:
            score = float(text)
            normalised["confidence"] = round(score * 100) if 0 <= score <= 1 else round(score)
        except ValueError:
            pass
    if isinstance(normalised.get("confidence"), float):
        score = normalised["confidence"]
        normalised["confidence"] = round(score * 100) if 0 <= score <= 1 else round(score)
    if "poc_kind" not in normalised and candidate in REVIEW_SCHEMA["properties"]["poc_kind"]["enum"]:
        normalised["poc_kind"] = candidate
    kind_aliases = {
        "command_execution": "command_injection",
        "command-execution": "command_injection",
        "rce": "command_injection",
        "directory_traversal": "path_traversal",
        "directory-traversal": "path_traversal",
        "open_redirect": "redirect",
    }
    if isinstance(normalised.get("poc_kind"), str):
        kind = normalised["poc_kind"].lower().replace(" ", "_").replace("-", "_")
        if "command" in kind or "exec" in kind or kind == "rce":
            kind = "command_injection"
        elif "traversal" in kind or "path" in kind or "file_read" in kind:
            kind = "path_traversal"
        elif "ssrf" in kind or "request_forgery" in kind:
            kind = "ssrf"
        normalised["poc_kind"] = kind_aliases.get(kind, kind)
    return normalised


def _parse_json_object(content: Any) -> dict[str, Any]:
    if not isinstance(content, str):
        raise ValueError("model response was not text")
    text = content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("model response was not a JSON object")
    return value


def _openai_review(client: Any, model: str, prompt: dict[str, str]) -> dict[str, Any]:
    response = client.responses.create(
        model=model,
        store=False,
        instructions="You are a secure-code reviewer. Decide if the provided static finding is likely real and recommend a defensive fix.",
        input=json.dumps(prompt, ensure_ascii=False),
        text={"format": {"type": "json_schema", "name": "security_review", "strict": True, "schema": REVIEW_SCHEMA}},
    )
    try:
        return _validate_assessment(_parse_json_object(response.output_text), "OpenAI")
    except (AttributeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("OpenAI returned an invalid structured review") from exc


def _deepseek_review(client: Any, model: str, prompt: dict[str, str]) -> dict[str, Any]:
    system = """You are a secure-code reviewer. Do not propose exploit chains or destructive payloads.
Return only a JSON object, with exactly these fields and JSON types:
{"confirmed": true, "confidence": 0, "summary": "", "impact": "", "recommended_fix": "", "poc_kind": "none"}
The poc_kind must be one of sql_injection, ssrf, path_traversal, command_injection, xss, redirect, none."""
    last_error: Exception | None = None
    # DeepSeek documents that JSON mode may occasionally return empty content.
    # One deterministic retry keeps the workflow automatic without unbounded use.
    for _ in range(2):
        response = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            max_tokens=1200,
            extra_body={"thinking": {"type": "disabled"}},
            messages=[{"role": "system", "content": system}, {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)}],
        )
        try:
            content = response.choices[0].message.content
            value = _normalise_deepseek_assessment(_parse_json_object(content), prompt["candidate_vulnerability"])
            return _validate_assessment(value, "DeepSeek")
        except (AttributeError, IndexError, TypeError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
            last_error = exc
    raise RuntimeError("DeepSeek returned an invalid structured review") from last_error


def review(finding: Finding, config: RunConfig, emit: Callable[[str, str, dict], None]) -> dict[str, Any]:
    load_runtime_env()
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("OpenAI SDK is not installed") from exc

    prompt = _prompt(finding)
    provider = config.ai_provider
    emit("ai_review", f"Reviewing {finding.rule_id} with {provider}", {"finding_id": finding.id, "provider": provider})
    if provider == "deepseek":
        if config.model not in {"deepseek-flash", "deepseek-v4-pro"}:
            raise RuntimeError("the selected model is not a supported DeepSeek model")
        key = os.getenv("DEEPSEEK_API_KEY")
        if not key:
            raise RuntimeError("DEEPSEEK_API_KEY is required when DeepSeek is selected")
        try:
            return _deepseek_review(OpenAI(api_key=key, base_url="https://api.deepseek.com"), config.model, prompt)
        except RuntimeError as exc:
            if "invalid structured review" not in str(exc):
                raise
            emit("ai_review", "DeepSeek returned no usable JSON conclusion; marking this finding for manual review", {"finding_id": finding.id, "provider": provider})
            return {
                "confirmed": False,
                "confidence": 0,
                "summary": "DeepSeek did not return a usable structured conclusion; manual review is required.",
                "impact": "No active validation was performed because the AI conclusion is inconclusive.",
                "recommended_fix": "Review the Semgrep finding manually and rerun after confirming the source context.",
                "poc_kind": "none",
            }

    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is required when OpenAI is selected")
    model = config.model or os.getenv("OPENAI_MODEL", "gpt-5.6-terra")
    if model not in {"gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.6-sol"}:
        raise RuntimeError("the selected model is not a supported OpenAI model")
    return _openai_review(OpenAI(api_key=key), model, prompt)
