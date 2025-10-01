from pydantic import BaseModel
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

class ScanStatus(Enum):
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"

class ScanSession(BaseModel):
    session_id: str
    target_urls: List[str]
    config: Dict[str, Any]
    status: ScanStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    class Config:
        use_enum_values = True

class VulnerabilityFinding(BaseModel):
    owasp_category: str
    vulnerability_name: str
    severity: str
    target_url: str
    successful_payload: Optional[str] = None
    evidence: Dict[str, Any] = {}
    remediation_steps: List[str] = []
    
class AgentResult(BaseModel):
    agent_name: str
    execution_time: float
    success: bool
    results: Dict[str, Any]
    errors: List[str] = []

class ScanResults(BaseModel):
    session_id: str
    overall_status: str
    targets_scanned: int
    vulnerabilities_found: int
    successful_exploits: int
    agent_results: List[AgentResult]
    vulnerability_findings: List[VulnerabilityFinding]
    executive_summary: Dict[str, Any]
    technical_report: Dict[str, Any]
    remediation_plan: Dict[str, Any]
    generated_at: datetime