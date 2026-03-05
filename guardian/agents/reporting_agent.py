"""
guardian/agents/reporting_agent.py
"""

import json
import logging
from typing import Any

from pydantic import BaseModel

from guardian.agents.base_agent import BaseAgent
from guardian.core.ai_client import ai_client, AIPersona, estimate_tokens

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Section schemas (Pydantic v2)
# ──────────────────────────────────────────────────────────────────────────────

class ExecutiveSummary(BaseModel):
    overall_risk_level: str
    business_impact: str
    critical_findings_count: int
    high_findings_count: int
    immediate_actions_required: list[str]


class TechnicalFinding(BaseModel):
    vulnerability_name: str
    owasp_category: str
    risk_level: str
    affected_components: list[str]
    technical_description: str
    proof_of_concept: str
    cvss_estimate: str


class RemediationItem(BaseModel):
    vulnerability_name: str
    priority: str
    remediation_steps: list[str]
    estimated_effort: str


class FullReport(BaseModel):
    report_title: str
    executive_summary: ExecutiveSummary | None
    technical_findings: list[TechnicalFinding]
    remediation_plan: list[RemediationItem]
    compliance_notes: list[str]
    scan_metadata: dict


# ──────────────────────────────────────────────────────────────────────────────
# Agent
# ──────────────────────────────────────────────────────────────────────────────

class ReportingAgent(BaseAgent):
    """
    Agent 5 — Professional Security Report Generation.

    Generates a full penetration testing report by decomposing the work into
    three bounded LLM calls rather than one unbounded dump.
    """

    def __init__(self, db) -> None:
        super().__init__(db, "ReportingAgent")

    # ── Entry point ───────────────────────────

    async def execute(self, task_data: dict[str, Any]) -> dict[str, Any]:
        task_id = await self._start_task(task_data)
        session_id = task_data.get("session_id", "unknown")

        try:
            all_results: dict[str, Any] = task_data.get("all_results", {})
            logger.info("ReportMaster generating report session_id=%s", session_id)

            # Step 1 — Compact context (safe for all LLM calls)
            ctx = self._build_report_context(all_results)
            ctx_tokens = estimate_tokens(json.dumps(ctx))
            logger.info("Report context built tokens≈%d", ctx_tokens)

            # Step 2 — Three decomposed LLM calls
            executive_summary = await self._generate_executive_summary(ctx)
            if executive_summary is None:
                executive_summary = self._fallback_executive_summary(ctx)
            technical_findings = await self._generate_technical_findings(ctx)
            remediation_plan = await self._generate_remediation_plan(ctx)

            # Step 3 — Assemble
            report = {
                "report_title": (
                    f"Guardian AI Security Assessment — "
                    f"{len(ctx.get('targets', []))} Target(s)"
                ),
                "executive_summary": executive_summary,
                "technical_findings": technical_findings,
                "remediation_plan": remediation_plan,
                "compliance_notes": self._generate_compliance_notes(ctx),
                "scan_metadata": {
                    "session_id": session_id,
                    "targets_assessed": ctx.get("total_targets", 0),
                    "vulnerabilities_found": len(ctx.get("confirmed_vulnerabilities", [])),
                    "successful_exploits": ctx.get("successful_exploits_count", 0),
                    "phases_completed": list(all_results.keys()),
                },
            }

            results = {"task_id": task_id, "report": report}
            await self._complete_task(results, session_id)
            logger.info(
                "ReportMaster complete session_id=%s findings=%d",
                session_id, len(technical_findings),
            )
            return results

        except Exception as exc:
            await self._handle_error(exc, session_id)
            raise

    # ── Results summariser (FIX 12) ───────────

    def _build_report_context(self, all_results: dict[str, Any]) -> dict[str, Any]:
        """
        Distil all pipeline results into a compact representation.
        Target: under 2,500 tokens regardless of input size.
        Raw HTTP responses, full payload lists, and verbose recon data
        are all excluded — only semantically necessary fields are kept.
        """
        ctx: dict[str, Any] = {
            "targets": [],
            "total_targets": 0,
            "confirmed_vulnerabilities": [],
            "successful_exploits_count": 0,
            "overall_risk": "Unknown",
        }

        # ── Recon summary ─────────────────────
        recon = all_results.get("reconnaissance", {})
        recon_map = recon.get("reconnaissance_data", {})
        ctx["total_targets"] = len(recon_map)

        for url, data in recon_map.items():
            if not isinstance(data, dict) or "error" in data:
                continue
            web = data.get("web_applications", {})
            ctx["targets"].append({
                "url": url,
                "technologies": [
                    t.get("name") if isinstance(t, dict) else str(t)
                    for tech_list in data.get("technologies", {}).values()
                    for t in tech_list
                ][:10],
                "open_ports": len(data.get("open_ports", [])),
                "endpoints_crawled": len(web.get("endpoints", [])),
                "forms_found": len(web.get("forms", [])),
                "subdomains_found": len(data.get("subdomains", [])),
                "attack_surface_score": data.get("attack_surface_score", 0),
            })

        # ── Vulnerability summary ─────────────
        vuln = all_results.get("vulnerability_analysis", {})
        assessment = vuln.get("vulnerability_assessment", vuln)
        ctx["overall_risk"] = assessment.get("overall_risk_level", "Unknown")
        ctx["identified_vulnerabilities"] = [
            {
                "name": v.get("vulnerability_name"),
                "owasp_category": v.get("owasp_category"),
                "risk_level": v.get("risk_level"),
                # reasoning truncated — not needed in report context
                "reasoning_excerpt": v.get("reasoning", "")[:200],
                "attack_vectors": v.get("attack_vectors", [])[:5],
            }
            for v in assessment.get("vulnerabilities", [])
        ]

        # ── Penetration results summary ───────
        pentest = all_results.get("penetration", {})
        for target_url, tdata in pentest.get("penetration_results", {}).items():
            for exploit in tdata.get("successful_exploits", []):
                ctx["confirmed_vulnerabilities"].append({
                    "target_url": target_url,
                    "vulnerability": exploit.get("vulnerability"),
                    "owasp_category": exploit.get("owasp_category"),
                    "impact_level": exploit.get("impact_level"),
                    # payload and HTTP evidence stripped — not needed for report generation
                    "evidence_summary": str(
                        exploit.get("evidence", {}).get("response_snippet", "")
                    )[:200],
                })
                ctx["successful_exploits_count"] += 1

        return ctx

    # ── Decomposed generation ─────────────────

    async def _generate_executive_summary(
        self, ctx: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Call 1 of 3 — focused, bounded executive summary prompt."""
        schema_hint = """{
  "overall_risk_level": "Critical|High|Medium|Low",
  "business_impact": "string",
  "critical_findings_count": 0,
  "high_findings_count": 0,
  "immediate_actions_required": ["string"]
}"""
        prompt = f"""Generate an executive summary for this security assessment.

ASSESSMENT DATA:
- Targets assessed: {ctx.get('total_targets', 0)}
- Overall risk: {ctx.get('overall_risk', 'Unknown')}
- Identified vulnerabilities: {len(ctx.get('identified_vulnerabilities', []))}
- Confirmed exploits: {ctx.get('successful_exploits_count', 0)}
- Vulnerability names: {[v.get('name') for v in ctx.get('identified_vulnerabilities', [])]}

Return ONLY valid JSON matching this schema (no markdown):
{schema_hint}"""

        self._check_prompt_tokens(prompt, "executive_summary")
        data, error = await ai_client.query_with_retry(
            prompt,
            schema_model=ExecutiveSummary,
            persona=AIPersona.SECURITY_REPORTER,
        )
        if error:
            logger.warning("Executive summary generation failed: %s", error)
            return None
        return data

    def _fallback_executive_summary(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """
        Deterministic executive summary built directly from context data.
        Used when the LLM call fails or returns unparseable output — ensures
        executive_summary is never null in the final report.
        """
        vulns = ctx.get("identified_vulnerabilities", [])
        confirmed = ctx.get("confirmed_vulnerabilities", [])
        overall_risk = ctx.get("overall_risk", "Low")

        critical_count = sum(1 for v in vulns if v.get("risk_level") == "Critical")
        high_count = sum(1 for v in vulns if v.get("risk_level") == "High")

        if not vulns:
            business_impact = (
                f"Assessment of {ctx.get('total_targets', 0)} target(s) completed. "
                "No vulnerabilities were identified during this assessment. "
                "The target presents a low attack surface based on reconnaissance data."
            )
            immediate_actions = ["No immediate actions required."]
        else:
            vuln_names = [v.get("name", "Unknown") for v in vulns[:3]]
            business_impact = (
                f"Assessment identified {len(vulns)} potential vulnerability/vulnerabilities "
                f"across {ctx.get('total_targets', 0)} target(s), with "
                f"{len(confirmed)} confirmed via active exploitation. "
                f"Key findings include: {', '.join(vuln_names)}."
            )
            immediate_actions = [
                f"Remediate {v.get('name')} ({v.get('owasp_category', '')})"
                for v in vulns
                if v.get("risk_level") in ("Critical", "High")
            ][:5] or ["Review and remediate identified vulnerabilities."]

        return {
            "overall_risk_level": overall_risk,
            "business_impact": business_impact,
            "critical_findings_count": critical_count,
            "high_findings_count": high_count,
            "immediate_actions_required": immediate_actions,
        }

    async def _generate_technical_findings(
        self, ctx: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Call 2 of 3 — one LLM call per vulnerability so each prompt
        is small and focused regardless of how many vulns were found.
        """
        findings: list[dict[str, Any]] = []

        confirmed_names = {
            v.get("vulnerability") for v in ctx.get("confirmed_vulnerabilities", [])
        }

        for vuln in ctx.get("identified_vulnerabilities", []):
            vuln_name = vuln.get("name", "Unknown")
            confirmed = vuln_name in confirmed_names
            exploit_info = next(
                (c for c in ctx.get("confirmed_vulnerabilities", [])
                 if c.get("vulnerability") == vuln_name),
                {},
            )

            schema_hint = """{
  "vulnerability_name": "string",
  "owasp_category": "string",
  "risk_level": "Critical|High|Medium|Low",
  "affected_components": ["string"],
  "technical_description": "string",
  "proof_of_concept": "string",
  "cvss_estimate": "string e.g. CVSS:3.1/AV:N/AC:L/..."
}"""
            prompt = f"""Write a technical finding entry for this vulnerability.

VULNERABILITY: {vuln_name}
OWASP CATEGORY: {vuln.get('owasp_category', '')}
RISK LEVEL: {vuln.get('risk_level', '')}
ATTACK VECTORS: {vuln.get('attack_vectors', [])}
CONFIRMED EXPLOITED: {confirmed}
EVIDENCE EXCERPT: {exploit_info.get('evidence_summary', 'N/A')}
IMPACT LEVEL: {exploit_info.get('impact_level', 'N/A')}

Return ONLY valid JSON (no markdown):
{schema_hint}"""

            self._check_prompt_tokens(prompt, f"technical_finding:{vuln_name}")
            data, error = await ai_client.query_with_retry(
                prompt,
                schema_model=TechnicalFinding,
                persona=AIPersona.SECURITY_REPORTER,
            )
            if error:
                logger.warning(
                    "Technical finding failed vuln=%s error=%s", vuln_name, error
                )
                findings.append({
                    "vulnerability_name": vuln_name,
                    "owasp_category": vuln.get("owasp_category", ""),
                    "risk_level": vuln.get("risk_level", "Unknown"),
                    "error": "Generation failed — see raw results",
                })
            else:
                findings.append(data)

        return findings

    async def _generate_remediation_plan(
        self, ctx: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Call 3 of 3 — batch all vulns in one call since remediation entries
        are brief and the full list stays within token budget.
        """
        vuln_list = [
            {
                "name": v.get("name"),
                "owasp_category": v.get("owasp_category"),
                "risk_level": v.get("risk_level"),
            }
            for v in ctx.get("identified_vulnerabilities", [])
        ]

        if not vuln_list:
            return []

        schema_hint = """[
  {
    "vulnerability_name": "string",
    "priority": "Immediate|High|Medium|Low",
    "remediation_steps": ["string"],
    "estimated_effort": "e.g. 2-4 hours"
  }
]"""
        prompt = f"""Generate a remediation plan for these vulnerabilities.

VULNERABILITIES:
{json.dumps(vuln_list, indent=2)}

Return ONLY a valid JSON array (no markdown):
{schema_hint}"""

        self._check_prompt_tokens(prompt, "remediation_plan")
        data, error = await ai_client.query_with_retry(
            prompt,
            persona=AIPersona.SECURITY_REPORTER,
        )

        if error or not isinstance(data, list):
            logger.warning("Remediation plan generation failed: %s", error)
            return []

        validated: list[dict] = []
        for item in data:
            try:
                validated.append(RemediationItem.model_validate(item).model_dump())
            except Exception:
                validated.append(item)
        return validated

    # ── Compliance notes ──────────────────────

    def _generate_compliance_notes(self, ctx: dict[str, Any]) -> list[str]:
        notes: list[str] = []
        vuln_cats = {
            v.get("owasp_category", "")
            for v in ctx.get("identified_vulnerabilities", [])
        }

        cat_compliance_map = {
            "A03:2023": "PCI DSS Req 6.3 (injection vulnerabilities must be prevented)",
            "A07:2023": "PCI DSS Req 8 (authentication controls) / HIPAA § 164.312(d)",
            "A02:2023": "PCI DSS Req 4 (encryption in transit) / HIPAA § 164.312(e)(2)(ii)",
            "A01:2023": "SOC 2 CC6.1 (logical access controls)",
            "A10:2023": "OWASP SSRF — review cloud metadata endpoint exposure",
        }

        for cat, note in cat_compliance_map.items():
            if cat in vuln_cats:
                notes.append(note)

        if not notes:
            notes.append("No specific compliance violations identified in this assessment.")

        return notes