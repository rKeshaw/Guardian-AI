from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def render_html_report(session_id: str, results: list[dict]) -> str:
    # Extract the reporting agent result
    report_data: dict[str, Any] = {}
    for r in results:
        if r.get("agent_name") == "reporting":
            report_data = r.get("results", {})
            break

    exec_summary = report_data.get("executive_summary", {})
    tech_findings = report_data.get("technical_findings", [])
    scan_meta = report_data.get("scan_metadata", {})
    generated_at = report_data.get("generated_at", datetime.now(timezone.utc).isoformat())

    severity_colors = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#16a34a"}

    findings_html = ""
    for f in tech_findings:
        severity = f.get("risk_level", f.get("cvss_score", 0))
        color = "#6b7280"
        if isinstance(severity, str):
            color = severity_colors.get(severity, "#6b7280")
        findings_html += f"""
        <div class="finding-card">
            <div class="finding-header">
                <span class="severity-badge" style="background:{color}">{f.get("risk_level","Unknown")}</span>
                <span class="owasp-badge">{f.get("owasp_category","")}</span>
                <span class="cwe-badge">{f.get("cwe","")}</span>
                <h3>{f.get("vulnerability_name","")}</h3>
            </div>
            <div class="cvss">CVSS {f.get("cvss_score","N/A")} — {f.get("cvss_vector","")}</div>
            <div class="description"><strong>Description:</strong> {f.get("description","")}</div>
            <div class="poc"><strong>Proof of Concept:</strong><pre>{f.get("proof_of_concept","")}</pre></div>
            <div class="remediation"><strong>Remediation:</strong> {f.get("remediation","")}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Guardian AI Security Report — {scan_meta.get("target_url","")}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0d0d1a;color:#e2e8f0;margin:0;padding:40px}}
h1,h2,h3{{color:#6366f1}} .finding-card{{background:#13131f;border:1px solid #2a2a45;border-radius:8px;padding:24px;margin:16px 0}}
.severity-badge,.owasp-badge,.cwe-badge{{display:inline-block;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:700;margin-right:8px}}
.owasp-badge{{background:#1e1e30;color:#94a3b8}} .cwe-badge{{background:#1e1e30;color:#6366f1}}
.cvss{{color:#f59e0b;font-family:monospace;margin:8px 0}} pre{{background:#0d0d1a;padding:12px;border-radius:4px;overflow-x:auto;font-size:13px}}
.description,.poc,.remediation{{margin:12px 0;line-height:1.6}}
</style></head>
<body>
<h1>Guardian AI Security Assessment Report</h1>
<div class="meta">Target: {scan_meta.get("target_url","")} | Session: {session_id} | Generated: {generated_at}</div>
<h2>Executive Summary</h2>
<p>{exec_summary.get("risk_overview","")}</p>
<h2>Technical Findings ({len(tech_findings)})</h2>
{findings_html}
</body></html>"""


def render_markdown_report(session_id: str, results: list[dict]) -> str:
    report_data: dict[str, Any] = {}
    for r in results:
        if r.get("agent_name") == "reporting":
            report_data = r.get("results", {})
            break

    exec_summary = report_data.get("executive_summary", {})
    tech_findings = report_data.get("technical_findings", [])
    scan_meta = report_data.get("scan_metadata", {})

    lines = [
        "# Guardian AI Security Report",
        f"**Target:** {scan_meta.get('target_url','')}",
        f"**Session:** {session_id}",
        f"**Generated:** {report_data.get('generated_at','')}",
        f"**Total Findings:** {len(tech_findings)}",
        "",
        "## Executive Summary",
        exec_summary.get("risk_overview", ""),
        "",
        "## Technical Findings",
    ]
    for i, f in enumerate(tech_findings, 1):
        lines += [
            f"### {i}. {f.get('vulnerability_name','')}",
            f"- **Severity:** {f.get('risk_level','')}",
            f"- **OWASP:** {f.get('owasp_category','')}",
            f"- **CWE:** {f.get('cwe','')}",
            f"- **CVSS:** {f.get('cvss_score','')} `{f.get('cvss_vector','')}`",
            "",
            f"**Description:** {f.get('description','')}",
            "",
            "**Proof of Concept:**",
            "```",
            f"{f.get('proof_of_concept','')}",
            "```",
            "",
            f"**Remediation:** {f.get('remediation','')}",
            "",
        ]
    return "\n".join(lines)

