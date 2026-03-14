from __future__ import annotations

import json
import logging
from datetime import datetime
from math import ceil
from typing import Any

from guardian.core.ai_client import AIPersona
from guardian.core.graph.attack_graph import AttackGraph, Node
from guardian.core.token_ledger import TokenLedger
from guardian.core.utils import charge_ledger, unpack_query_result

logger = logging.getLogger(__name__)


_OWASP_TO_CWE: dict[str, str] = {
    "A01:2023": "CWE-284",
    "A02:2023": "CWE-311",
    "A03:2023": "CWE-89",
    "A04:2023": "CWE-657",
    "A05:2023": "CWE-16",
    "A06:2023": "CWE-1104",
    "A07:2023": "CWE-287",
    "A08:2023": "CWE-502",
    "A09:2023": "CWE-778",
    "A10:2023": "CWE-918",
}


class ReportingAgent:
    def __init__(self, db, ai_client) -> None:
        self.db = db
        self.ai_client = ai_client

    async def generate(
        self,
        graph: AttackGraph,
        phase_results: dict,
        session_id: str,
        ledger: TokenLedger,
        deterministic_findings: list[dict[str, Any]] | None = None,
    ) -> dict:
        findings = graph.get_findings()

        report_context = {
            "session_id": session_id,
            "targets": phase_results.get("reconnaissance", {}).get("url", ""),
            "total_findings": len(findings),
            "findings": [
                {
                    "owasp_category": f.data.get("owasp_category"),
                    "hypothesis": f.data.get("hypothesis"),
                    "severity": (
                        f.data.get("exploitation_evidence", {}).get("severity", "unknown")
                        if f.data.get("exploitation_evidence")
                        else "unconfirmed"
                    ),
                    "proof_type": f.data.get("exploitation_evidence", {}).get("proof_type", ""),
                    "extracted_data": f.data.get("exploitation_evidence", {}).get("extracted_data", ""),
                    "payload_used": f.data.get("exploitation_evidence", {}).get("payload_used", ""),
                    "confirmed_facts": f.data.get("confirmed_facts", []),
                    "reasoning_chain_length": len(graph.get_path_to_root(f.id)),
                }
                for f in findings
            ],
        }

        executive_summary = await self._generate_executive_summary(report_context, ledger)
        deterministic_technical_findings = self._deterministic_technical_findings(deterministic_findings or [])
        llm_technical_findings = await self._generate_technical_findings(findings, graph, phase_results, ledger)
        technical_findings = deterministic_technical_findings + llm_technical_findings

        report = {
            "executive_summary": executive_summary,
            "technical_findings": technical_findings,
            "graph_summary": graph.stats(),
            "scan_metadata": {
                "session_id": session_id,
                "target_url": phase_results.get("reconnaissance", {}).get("url", ""),
                "total_findings": len(findings),
            },
            "generated_at": datetime.utcnow().isoformat(),
        }
        return report

    async def _generate_executive_summary(self, report_context: dict[str, Any], ledger: TokenLedger) -> dict[str, Any]:
        prompt = (
            "Generate an executive summary JSON for this security scan context. "
            "Return keys: risk_overview, key_findings, business_impact, immediate_actions.\n"
            f"Context:\n{json.dumps(report_context, indent=2)}"
        )
        if not charge_ledger(ledger, "reporting_agent", prompt):
            return self._executive_fallback(report_context)

        raw = await self.ai_client.query_with_retry(
            prompt,
            persona=AIPersona.SECURITY_REPORTER,
            max_retries=2,
        )
        payload = unpack_query_result(raw)
        if isinstance(payload, dict):
            return payload
        return self._executive_fallback(report_context)

    async def _generate_technical_findings(
        self,
        findings: list[Node],
        graph: AttackGraph,
        phase_results: dict,
        ledger: TokenLedger,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []

        for idx, finding in enumerate(findings):
            chain = [n.to_dict() for n in graph.get_path_to_root(finding.id)]

            auth_required = bool(phase_results.get("auth_required", False))
            finding_injection = finding.data.get("injection_point", {})
            finding_url = str(finding_injection.get("url", "")) if isinstance(finding_injection, dict) else ""
            page_classifications = phase_results.get("reconnaissance", {}).get("page_classifications", {})
            page_classification = page_classifications.get(finding_url, "general") if isinstance(page_classifications, dict) else "general"
            vector, score = self.compute_cvss(
                owasp_category=finding.data.get("owasp_category", ""),
                proof_type=finding.data.get("exploitation_evidence", {}).get("proof_type", ""),
                exploitation_confirmed=bool(finding.data.get("exploitation_evidence")),
                auth_required=auth_required,
                page_classification=page_classification,
            )

            if ledger.is_critical():
                out.append(self._technical_fallback(finding, chain, vector, score))
                continue

            prompt = (
                "Generate a technical finding JSON with keys: vulnerability_name, owasp_category, cvss_vector, "
                "description, proof_of_concept, remediation.\n"
                f"Finding data:\n{json.dumps(finding.data, indent=2)}\n\n"
                f"Reasoning chain:\n{json.dumps(chain, indent=2)}\n"
            )
            if not charge_ledger(ledger, "reporting_agent", prompt):
                out.extend(self._technical_fallback(f, [n.to_dict() for n in graph.get_path_to_root(f.id)], *self.compute_cvss(
                    owasp_category=f.data.get("owasp_category", ""),
                    proof_type=f.data.get("exploitation_evidence", {}).get("proof_type", ""),
                    exploitation_confirmed=bool(f.data.get("exploitation_evidence")),
                    auth_required=auth_required,
                    page_classification=(
                        phase_results.get("reconnaissance", {})
                        .get("page_classifications", {})
                        .get(str((f.data.get("injection_point", {}) or {}).get("url", "")), "general")
                        if isinstance(phase_results.get("reconnaissance", {}).get("page_classifications", {}), dict)
                        else "general"
                    ),
                )) for f in findings[idx:])
                break

            raw = await self.ai_client.query_with_retry(prompt, persona=AIPersona.SECURITY_REPORTER, max_retries=2)
            payload = unpack_query_result(raw)
            if isinstance(payload, dict):
                payload.setdefault("cvss_vector", vector)
                payload.setdefault("cvss_score", score)
                owasp = finding.data.get("owasp_category", "")
                payload["cwe"] = _OWASP_TO_CWE.get(owasp, "CWE-unknown")
                http_conf = finding.data.get("http_confirmation") if isinstance(finding.data, dict) else None
                if isinstance(http_conf, dict):
                    payload["http_confirmation"] = {
                        "confirmed": bool(http_conf.get("http_confirmed", False)),
                        "indicators": http_conf.get("new_indicators", []),
                        "impact_level": http_conf.get("impact_level", "None"),
                    }

                    if http_conf.get("http_confirmed"):
                        payload["proof_of_concept"] = (
                            str(payload.get("proof_of_concept", "")).strip()
                            + "\n\nHTTP confirmation: Targeted replay of exploitation payload produced differential indicators."
                        ).strip()
                    elif finding.data.get("exploitation_evidence"):
                        payload["proof_of_concept"] = (
                            str(payload.get("proof_of_concept", "")).strip()
                            + "\n\nNote: LLM reasoning confirmed this finding, but active HTTP replay did not reproduce differential indicators."
                        ).strip()
                out.append(payload)
            else:
                out.append(self._technical_fallback(finding, chain, vector, score))

        return out

    def _deterministic_technical_findings(self, deterministic_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for finding in deterministic_findings:
            if not isinstance(finding, dict):
                continue
            risk_level = str(finding.get("risk_level", "Low"))
            score = self._risk_level_score(risk_level)
            vector = self._risk_level_vector(risk_level)
            evidence = str(finding.get("evidence", ""))
            out.append(
                {
                    "vulnerability_name": finding.get("vulnerability_name", "Deterministic finding"),
                    "owasp_category": finding.get("owasp_category", "Unknown"),
                    "cwe": finding.get("cwe", ""),
                    "risk_level": risk_level,
                    "description": evidence,
                    "proof_of_concept": f"Deterministic check: {evidence}",
                    "remediation": finding.get("remediation", ""),
                    "deterministic": True,
                    "cvss_vector": vector,
                    "cvss_score": score,
                }
            )
        return out

    @staticmethod
    def _risk_level_score(risk_level: str) -> float:
        mapping = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
        }
        return mapping.get((risk_level or "").strip().lower(), 3.0)

    @staticmethod
    def _risk_level_vector(risk_level: str) -> str:
        key = (risk_level or "").strip().lower()
        if key == "critical":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        if key == "high":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        if key == "medium":
            return "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L"
        return "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"

    def _technical_fallback(self, finding: Node, chain: list[dict[str, Any]], vector: str, score: float) -> dict[str, Any]:
        probes = [n.get("data", {}).get("probe") for n in chain if n.get("type") == "probe" and n.get("data", {}).get("probe")]
        poc = (
            f"Observed reasoning chain of {len(chain)} nodes. "
            f"Probe(s): {probes[:3]} produced evidence: {finding.data.get('exploitation_evidence', {})}."
        )
        return {
            "vulnerability_name": finding.data.get("hypothesis", "Unknown finding"),
            "owasp_category": finding.data.get("owasp_category", "Unknown"),
            "cwe": _OWASP_TO_CWE.get(finding.data.get("owasp_category", ""), "CWE-unknown"),
            "cvss_vector": vector,
            "cvss_score": score,
            "description": finding.data.get("hypothesis", ""),
            "proof_of_concept": poc,
            "remediation": "Validate and sanitize inputs, apply least privilege, and patch affected components.",
            "http_confirmation": {
                "confirmed": bool((finding.data.get("http_confirmation") or {}).get("http_confirmed", False)),
                "indicators": (finding.data.get("http_confirmation") or {}).get("new_indicators", []),
                "impact_level": (finding.data.get("http_confirmation") or {}).get("impact_level", "None"),
            },
        }

    def _executive_fallback(self, ctx: dict[str, Any]) -> dict[str, Any]:
        return {
            "risk_overview": f"{ctx.get('total_findings', 0)} finding(s) detected.",
            "key_findings": [f.get("hypothesis", "") for f in ctx.get("findings", [])[:5]],
            "business_impact": "Confirmed vulnerabilities may expose data integrity/confidentiality risk.",
            "immediate_actions": ["Patch vulnerable components", "Restrict attack surface", "Re-test after remediation"],
        }

    def compute_cvss(
        self,
        *,
        owasp_category: str,
        proof_type: str,
        exploitation_confirmed: bool,
        auth_required: bool,
        page_classification: str = "general",
    ) -> tuple[str, float]:
        av = "N"
        ac = "L" if exploitation_confirmed else "H"
        if page_classification == "admin_page":
            pr = "H"
        elif auth_required:
            pr = "L"
        else:
            pr = "N"

        category = (owasp_category or "").lower()
        if "xss" in category or "a03" in category:
            ui = "R" if "xss" in category else "N"
        else:
            ui = "N"

        if proof_type == "rce":
            s = "C"
        else:
            s = "U"

        if proof_type == "rce":
            c, i, a = "H", "H", "H"
        elif proof_type == "data_extracted" or proof_type == "error_based":
            c, i, a = "H", "N", "N"
        elif proof_type == "reflected":
            c, i, a = "N", "L", "N"
        else:
            c, i, a = "L", "L", "L"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        score = self._cvss_base_score(av, ac, pr, ui, s, c, i, a)
        return vector, score

    def _cvss_base_score(self, av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> float:
        av_v = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[av]
        ac_v = {"L": 0.77, "H": 0.44}[ac]
        ui_v = {"N": 0.85, "R": 0.62}[ui]

        if s == "U":
            pr_v = {"N": 0.85, "L": 0.62, "H": 0.27}[pr]
        else:
            pr_v = {"N": 0.85, "L": 0.68, "H": 0.5}[pr]

        c_v = {"H": 0.56, "L": 0.22, "N": 0.0}[c]
        i_v = {"H": 0.56, "L": 0.22, "N": 0.0}[i]
        a_v = {"H": 0.56, "L": 0.22, "N": 0.0}[a]

        isc_base = 1 - ((1 - c_v) * (1 - i_v) * (1 - a_v))

        if s == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

        exploitability = 8.22 * av_v * ac_v * pr_v * ui_v

        if impact <= 0:
            return 0.0

        if s == "U":
            base = min(impact + exploitability, 10)
        else:
            base = min(1.08 * (impact + exploitability), 10)

        return self._round_up_1_decimal(base)

    @staticmethod
    def _round_up_1_decimal(value: float) -> float:
        return ceil(value * 10) / 10.0
