import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Union
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv

from autopenkit.models import AIAnalysis, NormalizedFinding
from autopenkit.utils import load_yaml_config, save_json


DEFAULT_PROVIDER = "gemini"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash-lite"
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_BATCH_SIZE = 1
AI_ANALYSIS_ITEM_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "finding_id": {"type": "STRING"},
        "ai_vulnerability_title": {"type": "STRING"},
        "ai_severity": {"type": "STRING"},
        "ai_confidence": {"type": "STRING"},
        "ai_explanation": {"type": "STRING"},
        "ai_likely_false_positive": {"type": "BOOLEAN"},
        "ai_false_positive_reason": {"type": "STRING", "nullable": True},
        "ai_business_impact": {"type": "STRING"},
        "ai_remediation": {"type": "STRING"},
        "ai_references": {
            "type": "ARRAY",
            "items": {"type": "STRING"},
        },
    },
    "required": [
        "finding_id",
        "ai_vulnerability_title",
        "ai_severity",
        "ai_confidence",
        "ai_explanation",
        "ai_likely_false_positive",
        "ai_business_impact",
        "ai_remediation",
        "ai_references",
    ],
}
GEMINI_RESPONSE_SCHEMA = {
    **AI_ANALYSIS_ITEM_SCHEMA,
    "required": [
        field
        for field in AI_ANALYSIS_ITEM_SCHEMA["required"]
        if field != "finding_id"
    ],
}
GEMINI_BATCH_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "analyses": {
            "type": "ARRAY",
            "items": AI_ANALYSIS_ITEM_SCHEMA,
        },
    },
    "required": ["analyses"],
}


class AIAnalysisError(RuntimeError):
    """Raised when AI analysis cannot be completed."""


def load_normalized_findings(path: Union[str, Path]) -> List[NormalizedFinding]:
    findings_path = Path(path)
    if not findings_path.exists():
        raise FileNotFoundError(f"Normalized findings file not found: {findings_path}")

    with findings_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return [NormalizedFinding(**item) for item in data]


def _analysis_placeholder(
    finding: NormalizedFinding,
    model: str,
    provider: str,
    reason: str,
) -> AIAnalysis:
    return AIAnalysis(
        finding_id=finding.finding_id,
        ai_vulnerability_title=finding.vulnerability_name,
        ai_severity=finding.severity,
        ai_confidence="unknown",
        ai_explanation=(
            "AI analysis was not performed. Review the normalized scanner evidence "
            "manually before treating this finding as confirmed."
        ),
        ai_likely_false_positive=False,
        ai_false_positive_reason=reason,
        ai_business_impact="Manual review required.",
        ai_remediation="Validate the finding and apply remediation guidance from the source tool.",
        ai_references=[],
        analyzed_at=datetime.now(timezone.utc),
        model_used=model,
        provider=provider,
        status="skipped",
    )


def _build_prompt(finding: NormalizedFinding, prompts: Dict[str, Any]) -> str:
    system_prompt = prompts.get("analyze_finding_system", "")
    user_template = prompts.get("analyze_finding_user_template", "")
    user_prompt = user_template.format(
        finding_id=finding.finding_id,
        vulnerability_name=finding.vulnerability_name,
        vulnerability_type=finding.vulnerability_type,
        severity=finding.severity,
        target=finding.target,
        url=finding.url,
        evidence=finding.evidence,
        tags=", ".join(finding.tags),
    )

    return (
        f"{system_prompt}\n\n{user_prompt}\n\n"
        "Return only one valid JSON object. Do not include markdown."
    )


def _finding_prompt_payload(finding: NormalizedFinding) -> Dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "vulnerability_name": finding.vulnerability_name,
        "vulnerability_type": finding.vulnerability_type,
        "severity": finding.severity,
        "target": finding.target,
        "url": finding.url,
        "evidence": finding.evidence,
        "tags": finding.tags,
    }


def _build_batch_prompt(
    findings: List[NormalizedFinding],
    prompts: Dict[str, Any],
) -> str:
    system_prompt = prompts.get("analyze_finding_system", "")
    findings_json = json.dumps(
        [_finding_prompt_payload(finding) for finding in findings],
        ensure_ascii=True,
        indent=2,
    )

    return (
        f"{system_prompt}\n\n"
        "Analyze each vulnerability finding in this JSON array:\n"
        f"{findings_json}\n\n"
        "Return exactly one valid JSON object with an analyses array. "
        "The analyses array must contain one object for each input finding, "
        "preserve every finding_id exactly, and include these fields for each item: "
        "finding_id, ai_vulnerability_title, ai_severity, ai_confidence, "
        "ai_explanation, ai_likely_false_positive, ai_false_positive_reason, "
        "ai_business_impact, ai_remediation, ai_references. "
        "Do not include markdown."
    )


def _extract_gemini_text(response_data: Dict[str, Any]) -> str:
    candidates = response_data.get("candidates") or []
    if not candidates:
        raise AIAnalysisError("Gemini response did not include candidates.")

    content = candidates[0].get("content") or {}
    parts = content.get("parts") or []
    texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
    text = "".join(texts).strip()

    if not text:
        raise AIAnalysisError("Gemini response did not include text content.")

    return text


def _parse_ai_json(text: str) -> Dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`").strip()
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        preview = cleaned[:160].replace("\n", " ")
        raise AIAnalysisError(
            f"AI provider returned invalid JSON: {exc.msg}. Preview: {preview}"
        ) from exc

    if not isinstance(data, dict):
        raise AIAnalysisError("AI provider returned JSON, but not a JSON object.")

    return data


def _gemini_models_to_try(ai_config: Dict[str, Any]) -> List[str]:
    primary_model = str(ai_config.get("model", DEFAULT_GEMINI_MODEL))
    fallback_models = [str(model) for model in ai_config.get("fallback_models", [])]
    models = [primary_model] + fallback_models
    unique_models: List[str] = []

    for model in models:
        if model and model not in unique_models:
            unique_models.append(model)

    return unique_models


def _is_retryable_gemini_error(error: AIAnalysisError) -> bool:
    message = str(error)
    return (
        "Gemini API error 429" in message
        or "Gemini API error 500" in message
        or "Gemini API error 502" in message
        or "Gemini API error 503" in message
        or "Gemini API error 504" in message
    )


def _call_gemini_model(
    prompt: str,
    ai_config: Dict[str, Any],
    model: str,
    response_schema: Dict[str, Any] = GEMINI_RESPONSE_SCHEMA,
) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise AIAnalysisError("GEMINI_API_KEY is not set.")

    timeout = int(ai_config.get("request_timeout", DEFAULT_TIMEOUT_SECONDS))
    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent"
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt,
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": float(ai_config.get("temperature", 0.1)),
            "maxOutputTokens": int(ai_config.get("max_tokens", 700)),
            "responseMimeType": "application/json",
            "responseSchema": response_schema,
        },
    }

    request = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-goog-api-key": api_key,
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AIAnalysisError(f"Gemini API error {exc.code}: {detail}") from exc
    except URLError as exc:
        raise AIAnalysisError(f"Gemini API request failed: {exc.reason}") from exc

    parsed = _parse_ai_json(_extract_gemini_text(response_data))
    parsed["_model_used"] = model
    return parsed


def _call_gemini(
    prompt: str,
    ai_config: Dict[str, Any],
    response_schema: Dict[str, Any] = GEMINI_RESPONSE_SCHEMA,
) -> Dict[str, Any]:
    max_retries = int(ai_config.get("max_retries", 2))
    retry_delay_seconds = float(ai_config.get("retry_delay_seconds", 2))
    errors: List[str] = []

    for model in _gemini_models_to_try(ai_config):
        for attempt in range(max_retries + 1):
            try:
                if response_schema == GEMINI_RESPONSE_SCHEMA:
                    return _call_gemini_model(prompt, ai_config, model)
                return _call_gemini_model(prompt, ai_config, model, response_schema)
            except AIAnalysisError as exc:
                errors.append(f"{model}: {exc}")
                if not _is_retryable_gemini_error(exc) or attempt >= max_retries:
                    break
                time.sleep(retry_delay_seconds * (attempt + 1))

    raise AIAnalysisError("All Gemini models failed. " + " | ".join(errors))


def _analysis_from_payload(
    finding: NormalizedFinding,
    analysis: Dict[str, Any],
    provider: str,
    model: str,
) -> AIAnalysis:
    return AIAnalysis(
        finding_id=finding.finding_id,
        ai_vulnerability_title=str(
            analysis.get("ai_vulnerability_title") or finding.vulnerability_name
        ),
        ai_severity=str(analysis.get("ai_severity") or finding.severity),
        ai_confidence=str(analysis.get("ai_confidence") or "unknown"),
        ai_explanation=str(analysis.get("ai_explanation") or ""),
        ai_likely_false_positive=bool(
            analysis.get("ai_likely_false_positive", False)
        ),
        ai_false_positive_reason=analysis.get("ai_false_positive_reason"),
        ai_business_impact=str(analysis.get("ai_business_impact") or ""),
        ai_remediation=str(analysis.get("ai_remediation") or ""),
        ai_references=[
            str(reference) for reference in analysis.get("ai_references", [])
        ],
        analyzed_at=datetime.now(timezone.utc),
        model_used=str(analysis.get("_model_used") or model),
        provider=str(provider),
    )


def analyze_finding(
    finding: NormalizedFinding,
    ai_config: Dict[str, Any],
    prompts: Dict[str, Any],
) -> AIAnalysis:
    provider = ai_config.get("provider", DEFAULT_PROVIDER)
    model = str(ai_config.get("model", DEFAULT_GEMINI_MODEL))

    if provider != "gemini":
        raise AIAnalysisError(f"Unsupported AI provider: {provider}")

    prompt = _build_prompt(finding, prompts)
    analysis = _call_gemini(prompt, ai_config)

    return _analysis_from_payload(finding, analysis, str(provider), model)


def _chunk_findings(
    findings: List[NormalizedFinding],
    batch_size: int,
) -> List[List[NormalizedFinding]]:
    return [
        findings[index : index + batch_size]
        for index in range(0, len(findings), batch_size)
    ]


def _normalize_batch_payload(
    response: Dict[str, Any],
    expected_findings: List[NormalizedFinding],
) -> Dict[str, Dict[str, Any]]:
    analyses = response.get("analyses")
    if not isinstance(analyses, list):
        raise AIAnalysisError("AI provider returned batch JSON without analyses array.")

    by_finding_id: Dict[str, Dict[str, Any]] = {}
    for item in analyses:
        if not isinstance(item, dict):
            raise AIAnalysisError("AI provider returned a non-object batch item.")
        finding_id = item.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise AIAnalysisError("AI provider returned a batch item without finding_id.")
        by_finding_id[finding_id] = item

    missing_ids = [
        finding.finding_id
        for finding in expected_findings
        if finding.finding_id not in by_finding_id
    ]
    if missing_ids:
        raise AIAnalysisError(
            "AI provider omitted batch analyses for finding IDs: "
            + ", ".join(missing_ids)
        )

    return by_finding_id


def _should_retry_batch_as_single(error: AIAnalysisError) -> bool:
    message = str(error)
    provider_failure_markers = [
        "GEMINI_API_KEY",
        "Unsupported AI provider",
        "Gemini API error 429",
        "Gemini API error 500",
        "Gemini API error 502",
        "Gemini API error 503",
        "Gemini API error 504",
        "Gemini API request failed",
    ]
    return not any(marker in message for marker in provider_failure_markers)


def analyze_finding_batch(
    findings: List[NormalizedFinding],
    ai_config: Dict[str, Any],
    prompts: Dict[str, Any],
) -> List[AIAnalysis]:
    if not findings:
        return []

    provider = ai_config.get("provider", DEFAULT_PROVIDER)
    model = str(ai_config.get("model", DEFAULT_GEMINI_MODEL))

    if provider != "gemini":
        raise AIAnalysisError(f"Unsupported AI provider: {provider}")

    prompt = _build_batch_prompt(findings, prompts)
    response = _call_gemini(prompt, ai_config, GEMINI_BATCH_RESPONSE_SCHEMA)
    by_finding_id = _normalize_batch_payload(response, findings)

    return [
        _analysis_from_payload(
            finding,
            {
                **by_finding_id[finding.finding_id],
                "_model_used": response.get("_model_used"),
            },
            str(provider),
            model,
        )
        for finding in findings
    ]


def analyze_findings(
    findings: List[NormalizedFinding],
    ai_config: Dict[str, Any],
    prompts: Dict[str, Any],
    skip_ai: bool = False,
) -> List[AIAnalysis]:
    provider = str(ai_config.get("provider", DEFAULT_PROVIDER))
    model = str(ai_config.get("model", DEFAULT_GEMINI_MODEL))
    fail_open = bool(ai_config.get("fail_open", True))
    batch_size = max(1, int(ai_config.get("batch_size", DEFAULT_BATCH_SIZE)))

    if skip_ai:
        return [
            _analysis_placeholder(finding, model, provider, "AI analysis skipped by user.")
            for finding in findings
        ]

    if batch_size <= 1:
        analyses: List[AIAnalysis] = []
        for finding in findings:
            try:
                analyses.append(analyze_finding(finding, ai_config, prompts))
            except AIAnalysisError as exc:
                if not fail_open:
                    raise
                analyses.append(_analysis_placeholder(finding, model, provider, str(exc)))
        return analyses

    analyses = []
    for batch in _chunk_findings(findings, batch_size):
        try:
            analyses.extend(analyze_finding_batch(batch, ai_config, prompts))
        except AIAnalysisError as exc:
            if not fail_open:
                raise
            if len(batch) == 1:
                analyses.append(_analysis_placeholder(batch[0], model, provider, str(exc)))
                continue

            if not _should_retry_batch_as_single(exc):
                analyses.extend(
                    _analysis_placeholder(finding, model, provider, str(exc))
                    for finding in batch
                )
                continue

            for finding in batch:
                try:
                    analyses.append(analyze_finding(finding, ai_config, prompts))
                except AIAnalysisError as fallback_exc:
                    analyses.append(
                        _analysis_placeholder(
                            finding,
                            model,
                            provider,
                            f"Batch analysis failed: {exc}. "
                            f"Single-finding fallback failed: {fallback_exc}",
                        )
                    )

    return analyses


def analyze_scan_output(
    output_dir: str,
    ai_config: Dict[str, Any],
    prompts_path: str = "config/prompts.yaml",
    skip_ai: bool = False,
) -> Dict[str, Any]:
    load_dotenv()

    output_path = Path(output_dir)
    findings = load_normalized_findings(output_path / "normalized_findings.json")
    prompts = load_yaml_config(prompts_path)
    analyses = analyze_findings(findings, ai_config, prompts, skip_ai=skip_ai)

    ai_output_path = output_path / "ai_analysis.json"
    save_json(analyses, str(ai_output_path))

    return {
        "ai_output_path": str(ai_output_path),
        "ai_analysis_count": len(analyses),
        "ai_analyzed_count": sum(1 for analysis in analyses if analysis.status == "analyzed"),
        "ai_skipped_count": sum(1 for analysis in analyses if analysis.status == "skipped"),
        "analyses": analyses,
    }
