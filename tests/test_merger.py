import json
from datetime import datetime, timezone

from autopenkit.merger import merge_findings, merge_scan_output
from autopenkit.models import AIAnalysis, NormalizedFinding
from autopenkit.reporter import generate_reports


def normalized_finding(finding_id="FIND-001", severity="info", severity_score=1):
    return NormalizedFinding(
        finding_id=finding_id,
        target="demo.testfire.net",
        asset="https://demo.testfire.net/swagger/index.html",
        vulnerability_name="Public Swagger API - Detect",
        vulnerability_type="exposure",
        severity=severity,
        severity_score=severity_score,
        source_tool="nuclei",
        template_id="swagger-api",
        evidence="Nuclei template matched at https://demo.testfire.net/swagger/index.html",
        url="https://demo.testfire.net/swagger/index.html",
        tags=["exposure", "api", "swagger"],
        timestamp="2026-06-21T02:34:00+07:00",
    )


def ai_analysis(finding_id="FIND-001", ai_severity="low", status="analyzed"):
    return AIAnalysis(
        finding_id=finding_id,
        ai_vulnerability_title="Public Swagger API",
        ai_severity=ai_severity,
        ai_confidence="medium",
        ai_explanation="A public Swagger UI was detected.",
        ai_likely_false_positive=False,
        ai_false_positive_reason=None,
        ai_business_impact="May expose API documentation.",
        ai_remediation="Restrict access if it is not intended to be public.",
        ai_affected_location="https://demo.testfire.net/swagger/index.html",
        ai_access_steps=[
            "Open the Swagger UI URL from an authorized browser session.",
            "Confirm whether the API documentation is intended to be public.",
        ],
        ai_owner_remediation_steps=[
            "Restrict Swagger UI to authenticated users or internal networks.",
        ],
        ai_fix_validation_steps=[
            "Reopen the URL and confirm the documentation is no longer public.",
        ],
        ai_references=["https://swagger.io/"],
        analyzed_at=datetime.now(timezone.utc),
        model_used="gemini-2.5-flash-lite",
        provider="gemini",
        status=status,
    )


def test_merge_findings_combines_normalized_and_ai_fields():
    final_findings = merge_findings(
        [normalized_finding()],
        [ai_analysis(ai_severity="low")],
    )

    assert len(final_findings) == 1
    final = final_findings[0]
    assert final.finding_id == "FIND-001"
    assert final.vulnerability_name == "Public Swagger API - Detect"
    assert final.ai_vulnerability_title == "Public Swagger API"
    assert final.final_severity == "low"
    assert final.final_severity_score == 2
    assert final.ai_status == "analyzed"
    assert final.ai_access_steps[0].startswith("Open the Swagger UI")


def test_merge_findings_keeps_finding_when_ai_analysis_is_missing():
    final_findings = merge_findings([normalized_finding()], [])

    assert len(final_findings) == 1
    final = final_findings[0]
    assert final.finding_id == "FIND-001"
    assert final.final_severity == "info"
    assert final.ai_status == "missing"
    assert final.ai_vulnerability_title is None


def test_merge_findings_normalizes_ai_severity_aliases():
    final_findings = merge_findings(
        [normalized_finding()],
        [ai_analysis(ai_severity="informational")],
    )

    assert final_findings[0].final_severity == "info"
    assert final_findings[0].final_severity_score == 1


def test_merge_scan_output_writes_final_findings_json(tmp_path):
    (tmp_path / "normalized_findings.json").write_text(
        json.dumps([normalized_finding().model_dump(mode="json")]),
        encoding="utf-8",
    )
    (tmp_path / "ai_analysis.json").write_text(
        json.dumps([ai_analysis().model_dump(mode="json")]),
        encoding="utf-8",
    )

    result = merge_scan_output(str(tmp_path))

    assert result["final_findings_count"] == 1
    assert result["findings_by_severity"]["low"] == 1
    assert (tmp_path / "final_findings.json").exists()

    saved = json.loads((tmp_path / "final_findings.json").read_text(encoding="utf-8"))
    assert saved[0]["finding_id"] == "FIND-001"
    assert saved[0]["ai_confidence"] == "medium"
    assert saved[0]["ai_owner_remediation_steps"][0].startswith("Restrict Swagger")


def test_generate_reports_writes_markdown_and_html(tmp_path):
    (tmp_path / "normalized_findings.json").write_text(
        json.dumps([normalized_finding().model_dump(mode="json")]),
        encoding="utf-8",
    )
    (tmp_path / "ai_analysis.json").write_text(
        json.dumps([ai_analysis().model_dump(mode="json")]),
        encoding="utf-8",
    )
    (tmp_path / "assets.json").write_text(
        json.dumps({"live_urls": ["https://demo.testfire.net"]}),
        encoding="utf-8",
    )
    (tmp_path / "scan_metadata.json").write_text(
        json.dumps(
            {
                "project_name": "AutoPenKit",
                "target": "https://demo.testfire.net",
                "profile": "safe",
                "scan_status": "completed",
                "total_assets": 1,
            }
        ),
        encoding="utf-8",
    )

    result = generate_reports(str(tmp_path), template_dir="templates")

    markdown_path = tmp_path / "reports" / "report.md"
    html_path = tmp_path / "reports" / "report.html"
    assert result["finding_count"] == 1
    assert markdown_path.exists()
    assert html_path.exists()
    assert "Public Swagger API" in markdown_path.read_text(encoding="utf-8")
    markdown = markdown_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")
    assert "How to Access and Verify" in markdown
    assert "Open the Swagger UI URL" in markdown
    assert "Security Report" in html
    assert "How to Access and Verify" in html
