from api_scan_tool.ai_review import _normalise_deepseek_assessment, _parse_json_object, _validate_assessment


def test_assessment_keeps_contract_fields_and_ignores_provider_metadata():
    result = _validate_assessment({
        "confirmed": True,
        "confidence": 92,
        "summary": "Command execution is reachable.",
        "impact": "Remote execution risk.",
        "recommended_fix": "Use a fixed command allowlist.",
        "poc_kind": "command_injection",
        "provider_reasoning": "This must not be persisted.",
    }, "DeepSeek")
    assert "provider_reasoning" not in result
    assert result["poc_kind"] == "command_injection"


def test_json_parser_accepts_a_markdown_fenced_object():
    assert _parse_json_object("```json\n{\"confirmed\": true}\n```") == {"confirmed": True}


def test_deepseek_aliases_normalise_to_the_review_contract():
    value = _normalise_deepseek_assessment({
        "is_vulnerable": True,
        "confidence": 90,
        "summary": "Reachable command execution.",
        "impact": "RCE.",
        "recommendation": "Use an allowlist.",
        "poc_kind": "command_execution",
    }, "command_injection")
    result = _validate_assessment(value, "DeepSeek")
    assert result["confirmed"] is True
    assert result["poc_kind"] == "command_injection"


def test_deepseek_normalises_common_value_variants():
    value = _normalise_deepseek_assessment({
        "isVulnerable": "yes",
        "confidence": "0.91",
        "summary": "Unsafe command execution.",
        "impact": "RCE.",
        "recommendedFix": "Use an allowlist.",
        "vulnerability_type": "command execution",
    }, "command_injection")
    result = _validate_assessment(value, "DeepSeek")
    assert result["confirmed"] is True
    assert result["confidence"] == 91
    assert result["poc_kind"] == "command_injection"
