import json
from pathlib import Path

import pytest

from autopenkit.normalizer import (
    NormalizationError,
    count_findings_by_severity,
    normalize_nuclei_jsonl,
    normalize_nuclei_records,
    normalize_scan_output,
    parse_jsonl,
)


def nuclei_record(
    template_id="swagger-api",
    name="Public Swagger API - Detect",
    severity="info",
    matched_at="https://demo.testfire.net:443/swagger/index.html",
    tags=None,
):
    return {
        "template-id": template_id,
        "info": {
            "name": name,
            "severity": severity,
            "tags": tags or ["exposure", "api", "swagger"],
        },
        "type": "http",
        "host": "demo.testfire.net",
        "url": "https://demo.testfire.net:443",
        "matched-at": matched_at,
        "timestamp": "2026-06-21T02:34:00.480598+07:00",
    }


def write_jsonl(path: Path, records):
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


def test_parse_jsonl_reads_non_empty_lines(tmp_path):
    jsonl_path = tmp_path / "nuclei.jsonl"
    record = nuclei_record()
    jsonl_path.write_text(json.dumps(record) + "\n\n", encoding="utf-8")

    assert parse_jsonl(jsonl_path) == [record]


def test_parse_jsonl_reports_invalid_json_line(tmp_path):
    jsonl_path = tmp_path / "nuclei.jsonl"
    jsonl_path.write_text('{"template-id": "ok"}\n{bad json}\n', encoding="utf-8")

    with pytest.raises(NormalizationError, match="Invalid JSON on line 2"):
        parse_jsonl(jsonl_path)


def test_normalize_nuclei_records_extracts_expected_schema():
    findings = normalize_nuclei_records([nuclei_record()])

    assert len(findings) == 1

    finding = findings[0]
    assert finding.finding_id == "FIND-001"
    assert finding.target == "demo.testfire.net"
    assert finding.asset == "https://demo.testfire.net:443/swagger/index.html"
    assert finding.vulnerability_name == "Public Swagger API - Detect"
    assert finding.vulnerability_type == "exposure"
    assert finding.severity == "info"
    assert finding.severity_score == 1
    assert finding.source_tool == "nuclei"
    assert finding.template_id == "swagger-api"
    assert finding.evidence == (
        "Nuclei template matched at https://demo.testfire.net:443/swagger/index.html"
    )
    assert finding.url == "https://demo.testfire.net:443/swagger/index.html"
    assert finding.tags == ["exposure", "api", "swagger"]
    assert finding.timestamp == "2026-06-21T02:34:00.480598+07:00"
    assert finding.is_duplicate is False


def test_normalize_nuclei_records_deduplicates_and_sorts_by_severity():
    duplicate_low = nuclei_record(
        template_id="missing-header",
        name="Missing Header",
        severity="low",
        matched_at="http://localhost:3000",
        tags=["headers"],
    )
    medium = nuclei_record(
        template_id="admin-panel",
        name="Admin Panel",
        severity="medium",
        matched_at="http://localhost:3000/admin",
        tags=["exposure", "panel"],
    )

    findings = normalize_nuclei_records([duplicate_low, medium, duplicate_low])

    assert [finding.finding_id for finding in findings] == ["FIND-001", "FIND-002"]
    assert [finding.template_id for finding in findings] == [
        "admin-panel",
        "missing-header",
    ]
    assert [finding.severity for finding in findings] == ["medium", "low"]


def test_count_findings_by_severity():
    findings = normalize_nuclei_records(
        [
            nuclei_record(severity="info"),
            nuclei_record(
                template_id="missing-header",
                severity="low",
                matched_at="http://localhost:3000",
            ),
        ]
    )

    assert count_findings_by_severity(findings) == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "info": 1,
    }


def test_normalize_scan_output_writes_normalized_findings_json(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    write_jsonl(raw_dir / "nuclei.jsonl", [nuclei_record()])

    result = normalize_scan_output(str(tmp_path))

    output_path = tmp_path / "normalized_findings.json"
    assert result["normalized_output_path"] == str(output_path)
    assert result["normalized_findings_count"] == 1
    assert output_path.exists()

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved[0]["finding_id"] == "FIND-001"
    assert saved[0]["template_id"] == "swagger-api"


def test_normalize_nuclei_jsonl_accepts_string_tags(tmp_path):
    jsonl_path = tmp_path / "nuclei.jsonl"
    write_jsonl(jsonl_path, [nuclei_record(tags="headers,misconfig")])

    findings = normalize_nuclei_jsonl(jsonl_path)

    assert findings[0].tags == ["headers", "misconfig"]
    assert findings[0].vulnerability_type == "headers"
