import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

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


def _update_report_metadata(
    output_path: Path,
    report_paths: Dict[str, str],
    generated_at: str,
) -> None:
    metadata_path = output_path / "scan_metadata.json"
    metadata = _load_json_if_exists(metadata_path, {})
    if not isinstance(metadata, dict):
        raise ReportError(f"Expected metadata object in {metadata_path}.")

    metadata["report_generated_at"] = generated_at
    metadata["report_paths"] = report_paths

    with metadata_path.open("w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2, ensure_ascii=False)


def _paragraph(text: Any, style: ParagraphStyle) -> Paragraph:
    value = "" if text is None else str(text)
    return Paragraph(escape(value), style)


def _bullet_list(items: List[str], style: ParagraphStyle) -> ListFlowable:
    flowables = [
        ListItem(_paragraph(item, style), leftIndent=12)
        for item in items
        if str(item).strip()
    ]
    return ListFlowable(flowables, bulletType="bullet", start="circle")


def _numbered_list(items: List[str], style: ParagraphStyle) -> ListFlowable:
    flowables = [
        ListItem(_paragraph(item, style), leftIndent=12)
        for item in items
        if str(item).strip()
    ]
    return ListFlowable(flowables, bulletType="1")


def _table(rows: List[List[Any]], col_widths: List[float]) -> Table:
    table = Table(rows, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _draw_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    canvas.drawRightString(
        A4[0] - doc.rightMargin,
        0.45 * inch,
        f"AutoPenKit Security Report - Page {doc.page}",
    )
    canvas.restoreState()


def _render_pdf_report(context: Dict[str, Any], pdf_path: Path) -> None:
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#111827"),
            spaceAfter=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1f2937"),
            spaceBefore=12,
            spaceAfter=8,
        )
    )
    body = styles["BodyText"]
    body.fontSize = 9
    body.leading = 12
    small = ParagraphStyle("Small", parent=body, fontSize=8, leading=10)

    metadata = context["metadata"]
    assets = context["assets"]
    findings = context["findings"]
    severity = context["findings_by_severity"]
    portfolio_summary = context["portfolio_summary"]
    target = metadata.get("target") or "unknown"

    story = [
        _paragraph(
            f"{metadata.get('project_name', 'AutoPenKit')} Security Assessment Report",
            styles["ReportTitle"],
        ),
        _table(
            [
                ["Field", "Value"],
                ["Target", target],
                ["Profile", metadata.get("profile", "unknown")],
                ["Scan status", metadata.get("scan_status", "unknown")],
                ["Overall risk", context["risk_level"]],
                ["Generated at", context["generated_at"]],
            ],
            [1.5 * inch, 4.8 * inch],
        ),
        Spacer(1, 0.15 * inch),
        _paragraph("1. Executive Summary", styles["SectionHeading"]),
        _paragraph(portfolio_summary["headline"], body),
        Spacer(1, 0.1 * inch),
        _table(
            [
                ["Metric", "Value"],
                ["Live assets", metadata.get("total_assets", len(assets.get("live_urls", [])))],
                ["Raw scanner findings", metadata.get("total_raw_findings", "N/A")],
                ["Normalized findings", metadata.get("total_normalized_findings", "N/A")],
                ["Final findings", context["finding_count"]],
                ["AI-analyzed findings", metadata.get("total_ai_analyzed_findings", context["ai_analyzed_count"])],
            ],
            [2.6 * inch, 3.7 * inch],
        ),
        _paragraph("Key Observations", styles["Heading4"]),
        _bullet_list(portfolio_summary["key_observations"], body),
        _paragraph("Remediation Themes", styles["Heading4"]),
        _bullet_list(portfolio_summary["remediation_themes"], body),
        _paragraph("Validation Priorities", styles["Heading4"]),
        _bullet_list(portfolio_summary["validation_priorities"], body),
        _paragraph("2. Severity Breakdown", styles["SectionHeading"]),
        _table(
            [
                ["Severity", "Count"],
                ["Critical", severity["critical"]],
                ["High", severity["high"]],
                ["Medium", severity["medium"]],
                ["Low", severity["low"]],
                ["Info", severity["info"]],
            ],
            [2.6 * inch, 3.7 * inch],
        ),
        _paragraph("3. Scope", styles["SectionHeading"]),
    ]

    live_urls = assets.get("live_urls", [])
    if live_urls:
        story.append(_bullet_list(live_urls, body))
    else:
        story.append(_paragraph("No live URLs were recorded for this scan.", body))

    story.extend(
        [
            _paragraph("4. Finding Overview", styles["SectionHeading"]),
        ]
    )
    if findings:
        overview_rows = [["ID", "Severity", "Owner", "Title", "URL"]]
        for finding in findings:
            overview_rows.append(
                [
                    _paragraph(finding["finding_id"], small),
                    _paragraph(finding["final_severity"].upper(), small),
                    _paragraph(finding.get("ai_remediation_owner") or "site owner", small),
                    _paragraph(
                        finding.get("ai_vulnerability_title")
                        or finding["vulnerability_name"],
                        small,
                    ),
                    _paragraph(finding["url"], small),
                ]
            )
        story.append(_table(overview_rows, [0.65 * inch, 0.7 * inch, 1.0 * inch, 2.0 * inch, 1.95 * inch]))
    else:
        story.append(_paragraph("No findings were produced.", body))

    story.append(PageBreak())
    story.append(_paragraph("5. Detailed Findings", styles["SectionHeading"]))
    if findings:
        for index, finding in enumerate(findings):
            if index:
                story.append(Spacer(1, 0.15 * inch))
            title = finding.get("ai_vulnerability_title") or finding["vulnerability_name"]
            story.append(
                _paragraph(
                    f"{finding['finding_id']} - {title}",
                    styles["Heading3"],
                )
            )
            story.append(
                _table(
                    [
                        ["Field", "Value"],
                        ["Final severity", finding["final_severity"].upper()],
                        ["Scanner severity", finding["severity"].upper()],
                        ["AI confidence", finding.get("ai_confidence") or "unknown"],
                        ["Validation status", finding.get("ai_validation_status") or "needs_manual_validation"],
                        ["Affected location", finding.get("ai_affected_location") or finding["url"]],
                    ],
                    [1.5 * inch, 4.8 * inch],
                )
            )
            story.append(Spacer(1, 0.08 * inch))
            story.append(_paragraph("Evidence", styles["Heading4"]))
            story.append(_paragraph(finding["evidence"], body))
            story.append(_paragraph("Analysis", styles["Heading4"]))
            story.append(
                _paragraph(
                    finding.get("ai_explanation")
                    or "No AI explanation was available. Manual validation is recommended.",
                    body,
                )
            )
            story.append(_paragraph("Recommended Remediation", styles["Heading4"]))
            story.append(
                _paragraph(
                    finding.get("ai_remediation")
                    or "Validate the finding and follow the source tool guidance.",
                    body,
                )
            )
            if finding.get("ai_owner_remediation_steps"):
                story.append(_paragraph("Owner Remediation Steps", styles["Heading4"]))
                story.append(_numbered_list(finding["ai_owner_remediation_steps"], body))
            if finding.get("ai_fix_validation_steps"):
                story.append(_paragraph("How to Confirm Fixed", styles["Heading4"]))
                story.append(_numbered_list(finding["ai_fix_validation_steps"], body))
            if finding.get("ai_references"):
                story.append(_paragraph("References", styles["Heading4"]))
                story.append(_bullet_list(finding["ai_references"], body))
    else:
        story.append(_paragraph("No detailed findings are available.", body))

    story.append(_paragraph("6. Notes", styles["SectionHeading"]))
    story.append(
        _bullet_list(
            [
                "AI-assisted analysis supports triage and should be manually validated before remediation decisions.",
                "Severity may be adjusted during final review when business context or exploitability differs from scanner output.",
            ],
            body,
        )
    )

    document = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
        title=f"AutoPenKit Security Report - {target}",
    )
    document.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)


def build_report_context(output_dir: str) -> Dict[str, Any]:
    output_path = Path(output_dir)
    final_findings = _load_final_findings(output_path)
    metadata = _load_json_if_exists(output_path / "scan_metadata.json", {})
    assets = _load_json_if_exists(output_path / "assets.json", {})
    findings_by_severity = count_final_findings_by_severity(final_findings)
    risk_level = _overall_risk_level(findings_by_severity)
    executive_action_plan = _build_executive_action_plan(final_findings)
    portfolio_summary = _build_portfolio_summary(
        final_findings,
        findings_by_severity,
        risk_level,
    )
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
        "portfolio_summary": portfolio_summary,
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


def _highest_severity(findings_by_severity: Dict[str, int]) -> str:
    for severity in ["critical", "high", "medium", "low", "info"]:
        if findings_by_severity.get(severity, 0) > 0:
            return severity
    return "none"


def _top_counts(values: List[str], limit: int = 3) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for value in values:
        normalized = (value or "unknown").strip() or "unknown"
        counts[normalized] = counts.get(normalized, 0) + 1

    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]


def _pluralize_findings(count: int) -> str:
    return "finding" if count == 1 else "findings"


def _build_portfolio_summary(
    findings: List[FinalFinding],
    findings_by_severity: Dict[str, int],
    risk_level: str,
) -> Dict[str, Any]:
    finding_count = len(findings)
    if finding_count == 0:
        return {
            "headline": (
                "No final findings were produced. Keep this report as evidence of "
                "the authorized scan scope and rerun with the right profile if coverage "
                "needs to expand."
            ),
            "key_observations": [
                "No scanner evidence was consolidated into final findings.",
                "Manual review should confirm the target and scan profile were appropriate.",
            ],
            "remediation_themes": [
                "No remediation themes were identified from this scan output.",
            ],
            "validation_priorities": [
                "Confirm the scan completed against the intended authorized target.",
            ],
        }

    highest_severity = _highest_severity(findings_by_severity)
    analyzed_count = sum(1 for finding in findings if finding.ai_status == "analyzed")
    likely_false_positive_count = sum(
        1 for finding in findings if finding.ai_likely_false_positive
    )
    validation_counts = _top_counts(
        [
            finding.ai_validation_status or "needs_manual_validation"
            for finding in findings
        ]
    )
    owner_counts = _top_counts(
        [finding.ai_remediation_owner or "site owner" for finding in findings]
    )
    technology_counts = _top_counts(
        [
            finding.ai_technology_context
            or finding.vulnerability_type
            or finding.template_id
            for finding in findings
        ]
    )

    headline = (
        f"AutoPenKit consolidated {finding_count} final "
        f"{_pluralize_findings(finding_count)}. The highest final severity is "
        f"{highest_severity.upper()}, producing an overall {risk_level} risk rating."
    )

    key_observations = [
        (
            f"{analyzed_count} of {finding_count} "
            f"{_pluralize_findings(finding_count)} include AI-assisted triage."
        ),
        (
            f"Validation status concentration: "
            f"{', '.join(f'{status} ({count})' for status, count in validation_counts)}."
        ),
        (
            f"{likely_false_positive_count} "
            f"{_pluralize_findings(likely_false_positive_count)} were marked as likely "
            "false positives by AI and should be manually checked before closure."
        ),
    ]

    remediation_themes = [
        (
            f"{owner} owns {count} {_pluralize_findings(count)} in the current report."
        )
        for owner, count in owner_counts
    ]
    remediation_themes.extend(
        [
            (
                f"Technology/theme focus: {technology} appears in {count} "
                f"{_pluralize_findings(count)}."
            )
            for technology, count in technology_counts
        ]
    )

    sorted_findings = sorted(
        findings,
        key=lambda finding: (
            -finding.final_severity_score,
            finding.finding_id,
        ),
    )
    validation_priorities = []
    for finding in sorted_findings[:5]:
        title = finding.ai_vulnerability_title or finding.vulnerability_name
        status = finding.ai_validation_status or "needs_manual_validation"
        validation_priorities.append(
            (
                f"{finding.finding_id} ({finding.final_severity.upper()}): "
                f"{title} - {status}. Next: {_first_step(finding)}"
            )
        )

    return {
        "headline": headline,
        "key_observations": key_observations,
        "remediation_themes": remediation_themes,
        "validation_priorities": validation_priorities,
    }


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

    pdf_path = reports_dir / "report.pdf"
    _render_pdf_report(context, pdf_path)
    report_paths["pdf"] = str(pdf_path)

    _update_report_metadata(output_path, report_paths, context["generated_at"])

    return {
        "reports_dir": str(reports_dir),
        "report_paths": report_paths,
        "finding_count": context["finding_count"],
        "findings_by_severity": context["findings_by_severity"],
    }
