import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from autopenkit.models import FinalFinding
from autopenkit.merger import count_final_findings_by_severity, merge_scan_output


class ReportError(RuntimeError):
    """Raised when a report cannot be generated."""


def _load_json_if_exists(path: Path, default: Any) -> Any:
    if not path.exists():
        return default

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _load_final_findings(output_path: Path) -> List[FinalFinding]:
    final_path = output_path / "final_findings.json"
    if not final_path.exists():
        merge_scan_output(str(output_path))

    data = _load_json_if_exists(final_path, [])
    if not isinstance(data, list):
        raise ReportError(f"Expected final findings list in {final_path}.")

    return [FinalFinding(**item) for item in data]


def _render_template(template_dir: Path, template_name: str, context: Dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(template_name)
    return template.render(**context)


def build_report_context(output_dir: str) -> Dict[str, Any]:
    output_path = Path(output_dir)
    final_findings = _load_final_findings(output_path)
    metadata = _load_json_if_exists(output_path / "scan_metadata.json", {})
    assets = _load_json_if_exists(output_path / "assets.json", {})
    findings_by_severity = count_final_findings_by_severity(final_findings)
    risk_level = _overall_risk_level(findings_by_severity)
    executive_action_plan = _build_executive_action_plan(final_findings)
    ai_analyzed_count = sum(
        1 for finding in final_findings if finding.ai_status == "analyzed"
    )

    return {
        "metadata": metadata,
        "assets": assets,
        "findings": [finding.model_dump(mode="json") for finding in final_findings],
        "finding_count": len(final_findings),
        "ai_analyzed_count": ai_analyzed_count,
        "findings_by_severity": findings_by_severity,
        "risk_level": risk_level,
        "executive_action_plan": executive_action_plan,
        "follow_up_scan_recommendations": _collect_follow_up_scan_recommendations(
            final_findings
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _overall_risk_level(findings_by_severity: Dict[str, int]) -> str:
    if findings_by_severity.get("critical", 0) > 0:
        return "Critical"
    if findings_by_severity.get("high", 0) > 0:
        return "High"
    if findings_by_severity.get("medium", 0) > 0:
        return "Medium"
    if findings_by_severity.get("low", 0) > 0:
        return "Low"
    if findings_by_severity.get("info", 0) > 0:
        return "Informational"
    return "No Findings"


def _recommended_timeline(finding: FinalFinding) -> str:
    severity = finding.final_severity.lower()
    if severity in {"critical", "high"}:
        return "Immediate"
    if severity == "medium":
        return "This week"
    if finding.ai_validation_status == "confirmed":
        return "This week"
    if finding.ai_validation_status == "likely_false_positive":
        return "Backlog after validation"
    return "Backlog or next maintenance window"


def _first_step(finding: FinalFinding) -> str:
    if finding.ai_access_steps:
        return finding.ai_access_steps[0]
    if finding.ai_owner_remediation_steps:
        return finding.ai_owner_remediation_steps[0]
    return "Validate the scanner evidence at the affected location."


def _build_executive_action_plan(
    findings: List[FinalFinding],
) -> List[Dict[str, str]]:
    plan = []
    for finding in findings:
        plan.append(
            {
                "finding_id": finding.finding_id,
                "title": finding.ai_vulnerability_title or finding.vulnerability_name,
                "severity": finding.final_severity,
                "timeline": _recommended_timeline(finding),
                "owner": finding.ai_remediation_owner or "site owner",
                "validation_status": (
                    finding.ai_validation_status or "needs_manual_validation"
                ),
                "rationale": finding.ai_priority_rationale
                or finding.ai_confidence_reason
                or "Prioritize after manual validation.",
                "next_step": _first_step(finding),
            }
        )
    return plan


def _collect_follow_up_scan_recommendations(
    findings: List[FinalFinding],
) -> List[str]:
    recommendations = []
    seen = set()
    for finding in findings:
        for recommendation in finding.ai_follow_up_scan_recommendations:
            normalized = recommendation.strip()
            if normalized and normalized not in seen:
                recommendations.append(normalized)
                seen.add(normalized)
    return recommendations


def generate_reports(
    output_dir: str,
    template_dir: str = "templates",
) -> Dict[str, Any]:
    output_path = Path(output_dir)
    reports_dir = output_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    template_path = Path(template_dir)
    if not template_path.exists():
        raise FileNotFoundError(f"Report template directory not found: {template_path}")

    context = build_report_context(output_dir)
    report_paths: Dict[str, str] = {}

    markdown_report = _render_template(template_path, "report.md.j2", context)
    markdown_path = reports_dir / "report.md"
    markdown_path.write_text(markdown_report, encoding="utf-8")
    report_paths["markdown"] = str(markdown_path)

    html_report = _render_template(template_path, "report.html.j2", context)
    html_path = reports_dir / "report.html"
    html_path.write_text(html_report, encoding="utf-8")
    report_paths["html"] = str(html_path)

    return {
        "reports_dir": str(reports_dir),
        "report_paths": report_paths,
        "finding_count": context["finding_count"],
        "findings_by_severity": context["findings_by_severity"],
    }
