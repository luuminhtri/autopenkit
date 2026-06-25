from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class ValidatedTarget(BaseModel):
    original_input: str
    scheme: str
    host: str
    port: int
    path: str
    is_authorized: bool
    validated_at: datetime


class AssetHost(BaseModel):
    host: str
    port: int
    scheme: str
    status: str
    service: str


class AssetsOutput(BaseModel):
    target: str
    scan_time: datetime
    hosts: List[AssetHost]
    live_urls: List[str]


class NormalizedFinding(BaseModel):
    finding_id: str
    target: str
    asset: str
    vulnerability_name: str
    vulnerability_type: str
    severity: str
    severity_score: int
    source_tool: str
    template_id: str
    evidence: str
    url: str
    tags: List[str]
    timestamp: Optional[str] = None
    is_duplicate: bool = False


class AIAnalysis(BaseModel):
    finding_id: str
    ai_vulnerability_title: str
    ai_severity: str
    ai_confidence: str
    ai_explanation: str
    ai_likely_false_positive: bool
    ai_false_positive_reason: Optional[str] = None
    ai_validation_status: Optional[str] = None
    ai_evidence_quality: Optional[str] = None
    ai_confidence_reason: Optional[str] = None
    ai_business_impact: str
    ai_remediation: str
    ai_priority_rationale: Optional[str] = None
    ai_remediation_owner: Optional[str] = None
    ai_technology_context: Optional[str] = None
    ai_affected_location: Optional[str] = None
    ai_access_steps: List[str] = Field(default_factory=list)
    ai_owner_remediation_steps: List[str] = Field(default_factory=list)
    ai_fix_validation_steps: List[str] = Field(default_factory=list)
    ai_config_examples: List[str] = Field(default_factory=list)
    ai_follow_up_scan_recommendations: List[str] = Field(default_factory=list)
    ai_references: List[str]
    analyzed_at: datetime
    model_used: str
    provider: str
    status: str = "analyzed"


class FinalFinding(BaseModel):
    finding_id: str
    target: str
    asset: str
    vulnerability_name: str
    vulnerability_type: str
    severity: str
    severity_score: int
    final_severity: str
    final_severity_score: int
    source_tool: str
    template_id: str
    evidence: str
    url: str
    tags: List[str]
    timestamp: Optional[str] = None
    is_duplicate: bool = False
    ai_vulnerability_title: Optional[str] = None
    ai_severity: Optional[str] = None
    ai_confidence: Optional[str] = None
    ai_explanation: Optional[str] = None
    ai_likely_false_positive: Optional[bool] = None
    ai_false_positive_reason: Optional[str] = None
    ai_validation_status: Optional[str] = None
    ai_evidence_quality: Optional[str] = None
    ai_confidence_reason: Optional[str] = None
    ai_business_impact: Optional[str] = None
    ai_remediation: Optional[str] = None
    ai_priority_rationale: Optional[str] = None
    ai_remediation_owner: Optional[str] = None
    ai_technology_context: Optional[str] = None
    ai_affected_location: Optional[str] = None
    ai_access_steps: List[str] = Field(default_factory=list)
    ai_owner_remediation_steps: List[str] = Field(default_factory=list)
    ai_fix_validation_steps: List[str] = Field(default_factory=list)
    ai_config_examples: List[str] = Field(default_factory=list)
    ai_follow_up_scan_recommendations: List[str] = Field(default_factory=list)
    ai_references: List[str] = Field(default_factory=list)
    ai_status: str = "missing"
    model_used: Optional[str] = None
    provider: Optional[str] = None


class ScanMetadata(BaseModel):
    scan_id: str
    project_name: str
    project_version: str
    target: str
    profile: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    modules_run: List[str]
    tools_used: List[str]
    total_assets: int = 0
    total_raw_findings: int = 0
    total_normalized_findings: int = 0
    total_ai_analyzed_findings: int = 0
    total_final_findings: int = 0
    findings_by_severity: dict = Field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
    )
    scan_status: str = "completed"
    scan_warning: Optional[str] = None
    ai_enabled: bool
    output_dir: str
