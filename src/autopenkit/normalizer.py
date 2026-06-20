import json
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, Union

from autopenkit.models import NormalizedFinding
from autopenkit.utils import save_json


SEVERITY_SCORES = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}


class NormalizationError(RuntimeError):
    """Raised when raw scanner output cannot be normalized."""


def _coerce_tags(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [str(tag).strip() for tag in value if str(tag).strip()]

    if isinstance(value, str):
        return [tag.strip() for tag in value.split(",") if tag.strip()]

    return [str(value).strip()] if str(value).strip() else []


def _severity_score(severity: str) -> int:
    return SEVERITY_SCORES.get(severity.lower(), SEVERITY_SCORES["unknown"])


def parse_jsonl(path: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Parse a JSON Lines file where each non-empty line is one JSON object.
    """

    jsonl_path = Path(path)
    if not jsonl_path.exists():
        raise FileNotFoundError(f"Nuclei JSONL file not found: {jsonl_path}")

    records: List[Dict[str, Any]] = []

    with jsonl_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise NormalizationError(
                    f"Invalid JSON on line {line_number} of {jsonl_path}: {exc.msg}"
                ) from exc

            if not isinstance(record, dict):
                raise NormalizationError(
                    f"Expected JSON object on line {line_number} of {jsonl_path}."
                )

            records.append(record)

    return records


def _raw_nuclei_to_payload(record: Dict[str, Any]) -> Dict[str, Any]:
    info = record.get("info") or {}
    if not isinstance(info, dict):
        info = {}

    template_id = str(
        record.get("template-id")
        or record.get("template_id")
        or record.get("template")
        or "unknown-template"
    )

    url = str(record.get("matched-at") or record.get("matched_at") or record.get("url") or "")
    target = str(record.get("host") or record.get("url") or url)
    tags = _coerce_tags(info.get("tags"))
    severity = str(info.get("severity") or "unknown").lower()
    name = str(info.get("name") or template_id)
    vulnerability_type = tags[0] if tags else str(record.get("type") or "unknown")

    return {
        "target": target,
        "asset": url or target,
        "vulnerability_name": name,
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "severity_score": _severity_score(severity),
        "source_tool": "nuclei",
        "template_id": template_id,
        "evidence": f"Nuclei template matched at {url or target}",
        "url": url or target,
        "tags": tags,
        "timestamp": record.get("timestamp"),
        "is_duplicate": False,
    }


def _deduplicate(payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[Tuple[str, str, str]] = set()
    unique_payloads: List[Dict[str, Any]] = []

    for payload in payloads:
        dedupe_key = (
            payload["template_id"],
            payload["url"],
            payload["severity"],
        )

        if dedupe_key in seen:
            continue

        seen.add(dedupe_key)
        unique_payloads.append(payload)

    return unique_payloads


def normalize_nuclei_records(records: List[Dict[str, Any]]) -> List[NormalizedFinding]:
    payloads = [_raw_nuclei_to_payload(record) for record in records]
    unique_payloads = _deduplicate(payloads)
    unique_payloads.sort(
        key=lambda payload: (
            -payload["severity_score"],
            payload["template_id"],
            payload["url"],
        )
    )

    return [
        NormalizedFinding(
            finding_id=f"FIND-{index:03d}",
            **payload,
        )
        for index, payload in enumerate(unique_payloads, start=1)
    ]


def normalize_nuclei_jsonl(path: Union[str, Path]) -> List[NormalizedFinding]:
    return normalize_nuclei_records(parse_jsonl(path))


def count_findings_by_severity(findings: List[NormalizedFinding]) -> Dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    return counts


def normalize_scan_output(output_dir: str) -> Dict[str, Any]:
    output_path = Path(output_dir)
    raw_path = output_path / "raw" / "nuclei.jsonl"
    normalized_path = output_path / "normalized_findings.json"

    findings = normalize_nuclei_jsonl(raw_path)
    save_json(findings, str(normalized_path))

    return {
        "normalized_output_path": str(normalized_path),
        "normalized_findings_count": len(findings),
        "findings_by_severity": count_findings_by_severity(findings),
        "findings": findings,
    }
