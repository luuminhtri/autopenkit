import json
from datetime import datetime, timezone

from autopenkit.ai_analysis import AIAnalysisError, analyze_findings, analyze_scan_output
from autopenkit.models import NormalizedFinding


def normalized_finding():
    return NormalizedFinding(
        finding_id="FIND-001",
        target="demo.testfire.net",
        asset="https://demo.testfire.net:443/swagger/index.html",
        vulnerability_name="Public Swagger API - Detect",
        vulnerability_type="exposure",
        severity="info",
        severity_score=1,
        source_tool="nuclei",
        template_id="swagger-api",
        evidence="Nuclei template matched at https://demo.testfire.net:443/swagger/index.html",
        url="https://demo.testfire.net:443/swagger/index.html",
        tags=["exposure", "api", "swagger"],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def normalized_finding_two():
    return normalized_finding().model_copy(
        update={
            "finding_id": "FIND-002",
            "asset": "https://demo.testfire.net:443",
            "vulnerability_name": "HTTP Missing Security Headers",
            "vulnerability_type": "misconfig",
            "template_id": "http-missing-security-headers",
            "evidence": "Nuclei template matched at https://demo.testfire.net:443",
            "url": "https://demo.testfire.net:443",
            "tags": ["misconfig", "headers"],
        }
    )


def test_analyze_findings_skip_ai_returns_placeholders():
    analyses = analyze_findings(
        findings=[normalized_finding()],
        ai_config={"provider": "gemini", "model": "gemini-2.5-flash-lite"},
        prompts={},
        skip_ai=True,
    )

    assert len(analyses) == 1
    assert analyses[0].finding_id == "FIND-001"
    assert analyses[0].status == "skipped"
    assert analyses[0].ai_confidence == "unknown"


def test_analyze_findings_missing_key_fail_open_returns_placeholder(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    analyses = analyze_findings(
        findings=[normalized_finding()],
        ai_config={
            "provider": "gemini",
            "model": "gemini-2.5-flash-lite",
            "fail_open": True,
        },
        prompts={
            "analyze_finding_system": "Return JSON.",
            "analyze_finding_user_template": "{finding_id} {vulnerability_name} {vulnerability_type} {severity} {target} {url} {evidence} {tags}",
        },
    )

    assert analyses[0].status == "skipped"
    assert analyses[0].ai_false_positive_reason is not None
    assert "GEMINI_API_KEY" in analyses[0].ai_false_positive_reason


def test_analyze_findings_invalid_ai_json_fail_open_returns_placeholder(monkeypatch):
    def fake_call_gemini(prompt, ai_config):
        from autopenkit.ai_analysis import _parse_ai_json

        return _parse_ai_json('{"ai_vulnerability_title": "Broken')

    monkeypatch.setattr("autopenkit.ai_analysis._call_gemini", fake_call_gemini)

    analyses = analyze_findings(
        findings=[normalized_finding()],
        ai_config={
            "provider": "gemini",
            "model": "gemini-2.5-flash-lite",
            "fail_open": True,
        },
        prompts={
            "analyze_finding_system": "Return JSON.",
            "analyze_finding_user_template": "{finding_id} {vulnerability_name} {vulnerability_type} {severity} {target} {url} {evidence} {tags}",
        },
    )

    assert analyses[0].status == "skipped"
    assert analyses[0].ai_false_positive_reason is not None
    assert "invalid JSON" in analyses[0].ai_false_positive_reason


def test_analyze_scan_output_writes_ai_analysis_json(monkeypatch, tmp_path):
    normalized_path = tmp_path / "normalized_findings.json"
    normalized_path.write_text(
        json.dumps([normalized_finding().model_dump(mode="json")]),
        encoding="utf-8",
    )

    prompts_path = tmp_path / "prompts.yaml"
    prompts_path.write_text(
        "\n".join(
            [
                "analyze_finding_system: |",
                "  Return JSON.",
                "analyze_finding_user_template: |",
                "  {finding_id} {vulnerability_name} {vulnerability_type} {severity} {target} {url} {evidence} {tags}",
            ]
        ),
        encoding="utf-8",
    )

    def fake_call_gemini(prompt, ai_config):
        return {
            "ai_vulnerability_title": "Public Swagger API",
            "ai_severity": "info",
            "ai_confidence": "medium",
            "ai_explanation": "A public Swagger UI was detected.",
            "ai_likely_false_positive": False,
            "ai_false_positive_reason": None,
            "ai_business_impact": "May expose API documentation.",
            "ai_remediation": "Restrict access if it is not intended to be public.",
            "ai_references": ["https://swagger.io/"],
            "_model_used": "gemini-2.5-flash-lite",
        }

    monkeypatch.setattr("autopenkit.ai_analysis._call_gemini", fake_call_gemini)

    result = analyze_scan_output(
        output_dir=str(tmp_path),
        ai_config={"provider": "gemini", "model": "gemini-2.5-flash-lite"},
        prompts_path=str(prompts_path),
    )

    assert result["ai_analysis_count"] == 1
    assert result["ai_analyzed_count"] == 1

    saved = json.loads((tmp_path / "ai_analysis.json").read_text(encoding="utf-8"))
    assert saved[0]["finding_id"] == "FIND-001"
    assert saved[0]["ai_confidence"] == "medium"
    assert saved[0]["provider"] == "gemini"


def test_analyze_findings_batches_multiple_findings(monkeypatch):
    calls = []

    def fake_call_gemini(prompt, ai_config, response_schema=None):
        calls.append(prompt)
        assert "FIND-001" in prompt
        assert "FIND-002" in prompt
        return {
            "analyses": [
                {
                    "finding_id": "FIND-001",
                    "ai_vulnerability_title": "Public Swagger API",
                    "ai_severity": "info",
                    "ai_confidence": "medium",
                    "ai_explanation": "A public Swagger UI was detected.",
                    "ai_likely_false_positive": False,
                    "ai_false_positive_reason": None,
                    "ai_business_impact": "May expose API documentation.",
                    "ai_remediation": "Restrict access if it is not intended to be public.",
                    "ai_references": ["https://swagger.io/"],
                },
                {
                    "finding_id": "FIND-002",
                    "ai_vulnerability_title": "Missing Security Headers",
                    "ai_severity": "info",
                    "ai_confidence": "high",
                    "ai_explanation": "Expected security headers were not present.",
                    "ai_likely_false_positive": False,
                    "ai_false_positive_reason": None,
                    "ai_business_impact": "May reduce browser-side protections.",
                    "ai_remediation": "Configure standard HTTP security headers.",
                    "ai_references": ["https://developer.mozilla.org/"],
                },
            ],
            "_model_used": "gemini-2.5-flash-lite",
        }

    monkeypatch.setattr("autopenkit.ai_analysis._call_gemini", fake_call_gemini)

    analyses = analyze_findings(
        findings=[normalized_finding(), normalized_finding_two()],
        ai_config={
            "provider": "gemini",
            "model": "gemini-2.5-flash-lite",
            "batch_size": 2,
        },
        prompts={"analyze_finding_system": "Return JSON."},
    )

    assert len(calls) == 1
    assert [analysis.finding_id for analysis in analyses] == ["FIND-001", "FIND-002"]
    assert all(analysis.status == "analyzed" for analysis in analyses)


def test_analyze_findings_does_not_single_fallback_after_quota_error(monkeypatch):
    calls = []

    def fake_call_gemini(prompt, ai_config, response_schema=None):
        calls.append(prompt)
        raise AIAnalysisError(
            "All Gemini models failed. gemini-2.5-flash-lite: "
            "Gemini API error 429: quota exceeded"
        )

    monkeypatch.setattr("autopenkit.ai_analysis._call_gemini", fake_call_gemini)

    analyses = analyze_findings(
        findings=[normalized_finding(), normalized_finding_two()],
        ai_config={
            "provider": "gemini",
            "model": "gemini-2.5-flash-lite",
            "batch_size": 2,
            "fail_open": True,
        },
        prompts={"analyze_finding_system": "Return JSON."},
    )

    assert len(calls) == 1
    assert [analysis.status for analysis in analyses] == ["skipped", "skipped"]
    assert "quota exceeded" in analyses[0].ai_false_positive_reason


def test_analyze_findings_uses_fallback_model_after_retryable_error(monkeypatch):
    calls = []

    def fake_call_gemini_model(prompt, ai_config, model):
        calls.append(model)
        if model == "gemini-2.5-flash-lite":
            raise AIAnalysisError("Gemini API error 503: overloaded")
        return {
            "ai_vulnerability_title": "Public Swagger API",
            "ai_severity": "info",
            "ai_confidence": "medium",
            "ai_explanation": "A public Swagger UI was detected.",
            "ai_likely_false_positive": False,
            "ai_false_positive_reason": None,
            "ai_business_impact": "May expose API documentation.",
            "ai_remediation": "Restrict access if it is not intended to be public.",
            "ai_references": ["https://swagger.io/"],
            "_model_used": model,
        }

    monkeypatch.setattr(
        "autopenkit.ai_analysis._call_gemini_model",
        fake_call_gemini_model,
    )
    monkeypatch.setattr("autopenkit.ai_analysis.time.sleep", lambda seconds: None)

    analyses = analyze_findings(
        findings=[normalized_finding()],
        ai_config={
            "provider": "gemini",
            "model": "gemini-2.5-flash-lite",
            "fallback_models": ["gemini-2.5-flash"],
            "max_retries": 0,
            "fail_open": True,
        },
        prompts={
            "analyze_finding_system": "Return JSON.",
            "analyze_finding_user_template": "{finding_id} {vulnerability_name} {vulnerability_type} {severity} {target} {url} {evidence} {tags}",
        },
    )

    assert calls == ["gemini-2.5-flash-lite", "gemini-2.5-flash"]
    assert analyses[0].status == "analyzed"
    assert analyses[0].model_used == "gemini-2.5-flash"
