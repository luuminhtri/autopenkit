import json
from pathlib import Path
from typing import Any, Dict, List, Union

from autopenkit.models import AIAnalysis, FinalFinding, NormalizedFinding
from autopenkit.normalizer import SEVERITY_SCORES, count_findings_by_severity
from autopenkit.utils import save_json


class MergeError(RuntimeError):
    """Raised when scan result files cannot be merged."""


SEVERITY_ALIASES = {
    "informational": "info",
    "moderate": "medium",
}


def _load_json(path: Union[str, Path]) -> Any:
    json_path = Path(path)
    if not json_path.exists():
        raise FileNotFoundError(f"JSON file not found: {json_path}")

    with json_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_normalized_findings(path: Union[str, Path]) -> List[NormalizedFinding]:
    data = _load_json(path)
    if not isinstance(data, list):
        raise MergeError(f"Expected normalized findings list in {path}.")
    return [NormalizedFinding(**item) for item in data]


def load_ai_analyses(path: Union[str, Path], required: bool = False) -> List[AIAnalysis]:
    analysis_path = Path(path)
    if not analysis_path.exists():
        if required:
            raise FileNotFoundError(f"AI analysis file not found: {analysis_path}")
        return []

    data = _load_json(analysis_path)
    if not isinstance(data, list):
        raise MergeError(f"Expected AI analysis list in {analysis_path}.")
    return [AIAnalysis(**item) for item in data]


def _normalize_severity(severity: str) -> str:
    normalized = severity.lower().strip()
    return SEVERITY_ALIASES.get(normalized, normalized)


def _severity_score(severity: str) -> int:
    return SEVERITY_SCORES.get(_normalize_severity(severity), SEVERITY_SCORES["unknown"])


def _final_severity(finding: NormalizedFinding, analysis: AIAnalysis) -> str:
    if analysis.ai_severity:
        return _normalize_severity(analysis.ai_severity)
    return finding.severity


def merge_findings(
    findings: List[NormalizedFinding],
    analyses: List[AIAnalysis],
) -> List[FinalFinding]:
    analyses_by_id = {analysis.finding_id: analysis for analysis in analyses}
    final_findings: List[FinalFinding] = []

    for finding in findings:
        analysis = analyses_by_id.get(finding.finding_id)
        if analysis is None:
            final_findings.append(
                FinalFinding(
                    **finding.model_dump(mode="json"),
                    final_severity=finding.severity,
                    final_severity_score=finding.severity_score,
                )
            )
            continue

        final_severity = _final_severity(finding, analysis)
        final_findings.append(
            FinalFinding(
                **finding.model_dump(mode="json"),
                final_severity=final_severity,
                final_severity_score=_severity_score(final_severity),
                ai_vulnerability_title=analysis.ai_vulnerability_title,
                ai_severity=analysis.ai_severity,
                ai_confidence=analysis.ai_confidence,
                ai_explanation=analysis.ai_explanation,
                ai_likely_false_positive=analysis.ai_likely_false_positive,
                ai_false_positive_reason=analysis.ai_false_positive_reason,
                ai_business_impact=analysis.ai_business_impact,
                ai_remediation=analysis.ai_remediation,
                ai_affected_location=analysis.ai_affected_location,
                ai_access_steps=analysis.ai_access_steps,
                ai_owner_remediation_steps=analysis.ai_owner_remediation_steps,
                ai_fix_validation_steps=analysis.ai_fix_validation_steps,
                ai_references=analysis.ai_references,
                ai_status=analysis.status,
                model_used=analysis.model_used,
                provider=analysis.provider,
            )
        )

    final_findings.sort(
        key=lambda finding: (
            -finding.final_severity_score,
            finding.finding_id,
        )
    )
    return final_findings


def count_final_findings_by_severity(findings: List[FinalFinding]) -> Dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        if finding.final_severity in counts:
            counts[finding.final_severity] += 1

    return counts


def merge_scan_output(output_dir: str) -> Dict[str, Any]:
    output_path = Path(output_dir)
    normalized_path = output_path / "normalized_findings.json"
    ai_analysis_path = output_path / "ai_analysis.json"
    final_output_path = output_path / "final_findings.json"

    findings = load_normalized_findings(normalized_path)
    analyses = load_ai_analyses(ai_analysis_path)
    final_findings = merge_findings(findings, analyses)
    save_json(final_findings, str(final_output_path))

    return {
        "final_output_path": str(final_output_path),
        "final_findings_count": len(final_findings),
        "findings_by_severity": count_final_findings_by_severity(final_findings),
        "normalized_findings_by_severity": count_findings_by_severity(findings),
        "ai_analysis_count": len(analyses),
        "final_findings": final_findings,
    }
