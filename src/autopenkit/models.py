from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


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
    total_final_findings: int = 0
    findings_by_severity: dict = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    ai_enabled: bool
    output_dir: str