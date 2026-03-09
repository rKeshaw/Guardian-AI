from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ReconPhaseOutput(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str
    domain: str
    technologies: list[str]
    waf_detected: str | None
    backend_language: str | None
    database_hint: str | None
    framework: str | None
    injection_points: list[dict]
    forms: list[dict]
    api_endpoints: list[str]
    html_comments: list[str]
    hardcoded_values: list[str]
    interesting_paths: list[str]
    open_ports: list[dict]
    attack_surface_signals: list[str]
    page_classifications: dict[str, str]


class HypothesisPhaseOutput(BaseModel):
    model_config = ConfigDict(extra="allow")

    hypotheses_generated: int
    seeded_from_vuln_analysis: int = 0


class VulnAnalysisPhaseOutput(BaseModel):
    model_config = ConfigDict(extra="allow")

    overall_risk_level: str
    vulnerabilities: list[dict]
    error: str | None = None
    skipped: bool = False


class GraphExplorationPhaseOutput(BaseModel):
    model_config = ConfigDict(extra="allow")

    finding_count: int
    graph_stats: dict
    active_confirmation_results: list[dict] = Field(default_factory=list)


class ReportPhaseOutput(BaseModel):
    model_config = ConfigDict(extra="allow")

    executive_summary: dict
    technical_findings: list[dict]
    graph_summary: dict
    scan_metadata: dict
    generated_at: str


class ScanPhaseResults(BaseModel):
    model_config = ConfigDict(extra="allow")

    reconnaissance: ReconPhaseOutput | None = None
    vulnerability_analysis: VulnAnalysisPhaseOutput | None = None
    hypothesis_seeding: HypothesisPhaseOutput | None = None
    graph_exploration: GraphExplorationPhaseOutput | None = None
    reporting: ReportPhaseOutput | None = None
