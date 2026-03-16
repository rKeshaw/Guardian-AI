from __future__ import annotations

import json
import logging
import uuid
from copy import deepcopy
from typing import Any

from pydantic import ValidationError

from aegis.core.ai_client import AIPersona, estimate_tokens
from aegis.core.graph.attack_graph import AttackGraph, Node, NodeType
from aegis.core.token_ledger import TokenLedger
from aegis.core.utils import charge_ledger, unpack_query_result
from aegis.models.hypothesis import HypothesisSchema

logger = logging.getLogger(__name__)


_REQUIRED_FIELDS = {
    "hypothesis",
    "owasp_category",
    "owasp_impact",
    "evidence_for",
    "evidence_against",
    "entry_probe",
    "expected_if_vulnerable",
    "expected_if_not_vulnerable",
    "confidence",
    "injection_point",
}

_REQUIRED_INJECTION_POINT_FIELDS = {"url", "method", "param_name", "param_type"}

TECH_HYPOTHESIS_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "wordpress": [
        {
            "hypothesis": "WordPress XML-RPC endpoint may allow brute-force amplification or pingback abuse",
            "owasp_category": "A07:2023",
            "owasp_impact": 6,
            "evidence_for": ["WordPress technology fingerprint detected", "xmlrpc.php commonly exposed in WordPress deployments"],
            "evidence_against": [],
            "entry_probe": "system.listMethods",
            "expected_if_vulnerable": "xmlrpc endpoint responds with method list or distinct XML-RPC behavior",
            "expected_if_not_vulnerable": "xmlrpc endpoint disabled or generic 404/403 response",
            "confidence": 62,
            "injection_point": {
                "url": "TARGET_URL/xmlrpc.php",
                "method": "POST",
                "param_name": "xml",
                "param_type": "form",
                "context_hint": "WordPress XML-RPC interface",
                "other_params": {"content_type": "text/xml"},
            },
        },
        {
            "hypothesis": "WordPress author enumeration may expose valid usernames via /?author=1",
            "owasp_category": "A01:2023",
            "owasp_impact": 5,
            "evidence_for": ["WordPress technology fingerprint detected"],
            "evidence_against": [],
            "entry_probe": "1",
            "expected_if_vulnerable": "Redirect or response reveals author slug/username",
            "expected_if_not_vulnerable": "No user-identifying redirect or profile information",
            "confidence": 58,
            "injection_point": {
                "url": "TARGET_URL/",
                "method": "GET",
                "param_name": "author",
                "param_type": "query",
                "context_hint": "WordPress author enumeration vector",
                "other_params": {},
            },
        },
    ],
    "django": [
        {
            "hypothesis": "Django debug mode exposure may reveal stack traces and sensitive settings",
            "owasp_category": "A05:2023",
            "owasp_impact": 7,
            "evidence_for": ["Django technology fingerprint detected"],
            "evidence_against": [],
            "entry_probe": "true",
            "expected_if_vulnerable": "Verbose Django debug traceback is returned",
            "expected_if_not_vulnerable": "Generic error page without debug internals",
            "confidence": 55,
            "injection_point": {
                "url": "TARGET_URL/",
                "method": "GET",
                "param_name": "debug",
                "param_type": "query",
                "context_hint": "Django debug-mode behavior check",
                "other_params": {},
            },
        },
        {
            "hypothesis": "Django admin endpoint may permit weak authentication or information disclosure",
            "owasp_category": "A07:2023",
            "owasp_impact": 6,
            "evidence_for": ["Django technology fingerprint detected", "admin routes commonly exposed"],
            "evidence_against": [],
            "entry_probe": "admin",
            "expected_if_vulnerable": "Distinct admin login/session behavior indicates weak protections",
            "expected_if_not_vulnerable": "Hardened admin authentication and no sensitive disclosure",
            "confidence": 53,
            "injection_point": {
                "url": "TARGET_URL/admin/",
                "method": "GET",
                "param_name": "next",
                "param_type": "query",
                "context_hint": "Django admin entry point",
                "other_params": {},
            },
        },
    ],
    "laravel": [
        {
            "hypothesis": "Laravel .env exposure could disclose APP_KEY and database credentials",
            "owasp_category": "A05:2023",
            "owasp_impact": 8,
            "evidence_for": ["Laravel technology fingerprint detected"],
            "evidence_against": [],
            "entry_probe": "1",
            "expected_if_vulnerable": "Response contains APP_KEY or DB_ variables",
            "expected_if_not_vulnerable": "Request blocked or no environment variables returned",
            "confidence": 64,
            "injection_point": {
                "url": "TARGET_URL/.env",
                "method": "GET",
                "param_name": "view",
                "param_type": "query",
                "context_hint": "Laravel environment file exposure check",
                "other_params": {},
            },
        },
        {
            "hypothesis": "Laravel telescope/debug endpoints may expose internal request and exception data",
            "owasp_category": "A05:2023",
            "owasp_impact": 7,
            "evidence_for": ["Laravel technology fingerprint detected"],
            "evidence_against": [],
            "entry_probe": "1",
            "expected_if_vulnerable": "Telescope/debug endpoint responds with internal telemetry",
            "expected_if_not_vulnerable": "Endpoint disabled, protected, or non-existent",
            "confidence": 57,
            "injection_point": {
                "url": "TARGET_URL/telescope",
                "method": "GET",
                "param_name": "page",
                "param_type": "query",
                "context_hint": "Laravel telescope endpoint check",
                "other_params": {},
            },
        },
    ],
    "php": [
        {
            "hypothesis": "phpinfo endpoint exposure may leak server modules, paths, and secrets",
            "owasp_category": "A05:2023",
            "owasp_impact": 6,
            "evidence_for": ["PHP technology fingerprint detected"],
            "evidence_against": [],
            "entry_probe": "1",
            "expected_if_vulnerable": "phpinfo page reveals runtime configuration",
            "expected_if_not_vulnerable": "Endpoint absent or denied",
            "confidence": 52,
            "injection_point": {
                "url": "TARGET_URL/phpinfo.php",
                "method": "GET",
                "param_name": "view",
                "param_type": "query",
                "context_hint": "PHP info disclosure check",
                "other_params": {},
            },
        },
    ],
    "graphql": [
        {
            "hypothesis": "GraphQL introspection may be enabled in production and expose full schema",
            "owasp_category": "A01:2023",
            "owasp_impact": 6,
            "evidence_for": ["GraphQL endpoint detected"],
            "evidence_against": [],
            "entry_probe": "{__schema{types{name}}}",
            "expected_if_vulnerable": "Introspection query returns schema metadata",
            "expected_if_not_vulnerable": "Introspection blocked or sanitized",
            "confidence": 60,
            "injection_point": {
                "url": "TARGET_URL/graphql",
                "method": "POST",
                "param_name": "query",
                "param_type": "json",
                "context_hint": "GraphQL introspection probe",
                "other_params": {"operationName": "IntrospectionQuery"},
            },
        },
        {
            "hypothesis": "GraphQL query parameter may permit injection-like manipulation of resolver behavior",
            "owasp_category": "A03:2023",
            "owasp_impact": 7,
            "evidence_for": ["GraphQL endpoint detected", "query parameter accepted"],
            "evidence_against": [],
            "entry_probe": "{user(id:\"1\") {id name}}",
            "expected_if_vulnerable": "Unexpected resolver errors or unauthorized object access",
            "expected_if_not_vulnerable": "Strict validation and authorization enforcement",
            "confidence": 56,
            "injection_point": {
                "url": "TARGET_URL/graphql",
                "method": "GET",
                "param_name": "query",
                "param_type": "query",
                "context_hint": "GraphQL query parameter testing",
                "other_params": {},
            },
        },
    ],
}

class HypothesisAgent:
    def __init__(self, db: Any, ai_client: Any) -> None:
        self.db = db
        self.ai_client = ai_client

    async def generate(
        self,
        target_model: dict,
        graph: AttackGraph,
        ledger: TokenLedger,
    ) -> list[Node]:
        prompt = self._build_generation_prompt(target_model)

        if not charge_ledger(ledger, "hypothesis_engine", prompt):
            logger.warning("Token budget exhausted before hypothesis generation.")
            return []

        persona = AIPersona.HYPOTHESIS_ENGINE
        raw_first = await self.ai_client.query_with_retry(
            prompt,
            persona=persona,
            max_retries=2,
        )

        initial_payload = unpack_query_result(raw_first)
        if initial_payload is None:
            logger.warning("Hypothesis generation returned no payload.")
            return []

        hypotheses = self._extract_hypothesis_list(initial_payload)
        tech_seeded = self._get_technology_hypotheses(target_model, target_model.get("injection_points", []))
        cve_seeded = self._get_cve_hypotheses(target_model)
        hypotheses = hypotheses + tech_seeded + cve_seeded
        valid = self._validate_hypotheses(hypotheses)

        reviewed = await self._self_review(target_model, valid, ledger, persona)
        deduped = self._deduplicate(reviewed)

        nodes = [self._to_node(h) for h in deduped]
        nodes.sort(key=lambda n: n.confidence, reverse=True)

        for node in nodes:
            graph.add_node(node)

        return nodes

    def _build_generation_prompt(self, target_model: dict[str, Any]) -> str:
        technologies = target_model.get("technologies", [])
        injection_points = target_model.get("injection_points", [])
        attack_surface_signals = target_model.get("attack_surface_signals", target_model.get("interesting_signals", []))
        waf = target_model.get("waf_detected", target_model.get("waf", "not detected"))

        compact_model = {
            "technologies": technologies,
            "injection_points": injection_points,
            "attack_surface_signals": attack_surface_signals,
            "waf_detected": waf,
        }

        examples = [
            {
                "hypothesis": "The LOGIN_PARAM field on PLACEHOLDER_LOGIN_URL is injectable via error-based SQLi",
                "owasp_category": "A03:2023",
                "owasp_impact": 9,
                "evidence_for": ["Database technology detected", "input reaches backend query context"],
                "evidence_against": ["WAF may sanitize some payloads"],
                "entry_probe": "'",
                "expected_if_vulnerable": "SQL syntax error or differential query behavior in response",
                "expected_if_not_vulnerable": "Normal application flow with no SQL artifacts",
                "confidence": 70,
                "injection_point": {
                    "url": "PLACEHOLDER_LOGIN_URL",
                    "method": "POST",
                    "param_name": "LOGIN_PARAM",
                    "param_type": "form",
                    "context_hint": "login input",
                    "other_params": {"password": "test"}
                }
            },
            {
                "hypothesis": "Authentication bypass is possible via PASSWORD_PARAM on PLACEHOLDER_AUTH_URL",
                "owasp_category": "A07:2023",
                "owasp_impact": 8,
                "evidence_for": ["Authentication endpoint discovered", "credential-bearing form parameters detected"],
                "evidence_against": ["MFA or lockout may be enabled"],
                "entry_probe": "' OR '1'='1",
                "expected_if_vulnerable": "Authentication logic can be bypassed or inconsistent auth state observed",
                "expected_if_not_vulnerable": "Strict auth validation and stable failed-login behavior",
                "confidence": 62,
                "injection_point": {
                    "url": "PLACEHOLDER_AUTH_URL",
                    "method": "POST",
                    "param_name": "PASSWORD_PARAM",
                    "param_type": "form",
                    "context_hint": "password/authentication parameter",
                    "other_params": {"username": "tester"}
                }
            },
            {
                "hypothesis": "Path traversal may be possible through FILE_PARAM on PLACEHOLDER_FILE_URL",
                "owasp_category": "A01:2023",
                "owasp_impact": 7,
                "evidence_for": ["File/resource parameter discovered", "backend file handling likely"],
                "evidence_against": ["Canonicalization and allowlists may be implemented"],
                "entry_probe": "../../../../etc/passwd",
                "expected_if_vulnerable": "File content leakage or traversal-related errors occur",
                "expected_if_not_vulnerable": "Parameter rejected or normalized to safe resource",
                "confidence": 58,
                "injection_point": {
                    "url": "PLACEHOLDER_FILE_URL",
                    "method": "GET",
                    "param_name": "FILE_PARAM",
                    "param_type": "query",
                    "context_hint": "file/path parameter",
                    "other_params": {}
                }
            },
            {
                "hypothesis": "SSRF may be exploitable via URL_PARAM on PLACEHOLDER_CALLBACK_URL",
                "owasp_category": "A10:2023",
                "owasp_impact": 8,
                "evidence_for": ["URL/webhook callback parameter discovered"],
                "evidence_against": ["Outbound network egress controls may exist"],
                "entry_probe": "http://169.254.169.254/latest/meta-data/",
                "expected_if_vulnerable": "Server-side request behavior or metadata access indicators appear",
                "expected_if_not_vulnerable": "Remote URL fetch restricted and no internal reachability evidence",
                "confidence": 61,
                "injection_point": {
                    "url": "PLACEHOLDER_CALLBACK_URL",
                    "method": "POST",
                    "param_name": "URL_PARAM",
                    "param_type": "form",
                    "context_hint": "URL callback parameter",
                    "other_params": {}
                }
            },
            {
                "hypothesis": "Security misconfiguration may expose privileged behavior via DEBUG_PARAM on PLACEHOLDER_ADMIN_URL",
                "owasp_category": "A05:2023",
                "owasp_impact": 6,
                "evidence_for": ["Administrative/debug paths present in attack surface"],
                "evidence_against": ["Production hardening may disable debug features"],
                "entry_probe": "true",
                "expected_if_vulnerable": "Debug/admin internals or verbose errors are exposed",
                "expected_if_not_vulnerable": "No debug details and access controls enforced",
                "confidence": 55,
                "injection_point": {
                    "url": "PLACEHOLDER_ADMIN_URL",
                    "method": "GET",
                    "param_name": "DEBUG_PARAM",
                    "param_type": "query",
                    "context_hint": "debug/config parameter",
                    "other_params": {}
                }
            },
        ]

        lines = [
            "Generate 5 to 15 penetration testing hypotheses as a JSON array.",
            "Return ONLY the JSON array. No markdown. No explanation before or after.",
            "Each element must have ALL of these keys exactly:",
            "hypothesis, owasp_category, owasp_impact, evidence_for, evidence_against,",
            "entry_probe, expected_if_vulnerable, expected_if_not_vulnerable, confidence, injection_point.",
            "injection_point must have: url, method, param_name, param_type, context_hint, other_params.",
            "owasp_category must match pattern A##:2023.",
            "confidence is integer 0-100. owasp_impact is integer 1-10.",
            "Every hypothesis must name a specific parameter from the target data below.",
            "Generate at least one hypothesis per OWASP category present in the attack surface signals. Ensure coverage across access control, injection, authentication, and configuration categories. Do not generate more than 4 hypotheses for any single OWASP category.",
            "",
            "Examples of valid elements (replace PLACEHOLDER_* and *_PARAM with actual target values):",
            json.dumps(examples, indent=2),
            "",
            "Target reconnaissance data:",
            json.dumps(compact_model, indent=2),
            "",
            "Return the JSON array now:",
        ]
        return "\n".join(lines)


    def _get_technology_hypotheses(self, target_model: dict[str, Any], injection_points: list[dict]) -> list[dict[str, Any]]:
        technologies = [str(t).lower() for t in target_model.get("technologies", [])]
        fallback_url = str(target_model.get("url", "TARGET_URL"))
        base_url = fallback_url
        if injection_points and isinstance(injection_points[0], dict):
            base_url = str(injection_points[0].get("url", fallback_url))

        seeded: list[dict[str, Any]] = []
        for tech_key, templates in TECH_HYPOTHESIS_TEMPLATES.items():
            if not any(tech_key in t for t in technologies):
                continue
            for template in templates:
                item = deepcopy(template)
                inj = item.get("injection_point", {})
                if isinstance(inj, dict):
                    inj_url = str(inj.get("url", ""))
                    inj["url"] = inj_url.replace("TARGET_URL", base_url.rstrip("/"))
                    item["injection_point"] = inj
                seeded.append(item)
        return seeded

    def _get_cve_hypotheses(self, target_model: dict[str, Any]) -> list[dict[str, Any]]:
        seeded: list[dict[str, Any]] = []
        cves = target_model.get("cve_correlations", []) or []
        fallback_url = str(target_model.get("url", "TARGET_URL"))
        default_ip = {
            "url": fallback_url,
            "method": "GET",
            "param_name": "path",
            "param_type": "query",
            "context_hint": "cve correlation seed",
            "other_params": {},
        }
        for cve in cves[:10]:
            cve_id = str(cve.get("cve_id", "")).strip()
            if not cve_id:
                continue
            score = float(cve.get("cvss_score") or 8.0)
            conf = max(80, min(98, int(score * 10)))
            seeded.append({
                "hypothesis": f"Detected component may be vulnerable to {cve_id}",
                "owasp_category": "A06:2023",
                "owasp_impact": max(7, min(10, int(round(score)))),
                "evidence_for": [
                    f"CVE correlation: {cve_id}",
                    f"Technology: {cve.get('tech')} {cve.get('version')}",
                    str(cve.get("description", ""))[:240],
                ],
                "evidence_against": [],
                "entry_probe": "version fingerprint",
                "expected_if_vulnerable": "Known vulnerable component/version observed in target surface",
                "expected_if_not_vulnerable": "Version fingerprint is incomplete or patched build is in use",
                "confidence": conf,
                "injection_point": default_ip,
            })
        return seeded

    async def _self_review(
        self,
        target_model: dict[str, Any],
        hypotheses: list[dict[str, Any]],
        ledger: TokenLedger,
        persona: AIPersona,
    ) -> list[dict[str, Any]]:
        technologies = target_model.get("technologies", [])
        review_prompt = (
            "Review this hypothesis list for a target with the following technologies: "
            f"{technologies}.\n"
            "Are there obvious high-impact hypotheses missing? Are any hypotheses redundant?\n"
            "Return a JSON object with keys 'missing' (list of new hypothesis dicts) "
            "and 'redundant' (list of hypothesis strings to remove by hypothesis text match).\n"
            f"Current list:\n{json.dumps(hypotheses, indent=2)}"
        )

        if not charge_ledger(ledger, "hypothesis_engine", review_prompt):
            logger.warning("Token budget exhausted before self-review pass.")
            return hypotheses

        raw_review = await self.ai_client.query_with_retry(
            review_prompt,
            persona=persona,
            max_retries=2,
        )
        review_payload = unpack_query_result(raw_review)
        if not isinstance(review_payload, dict):
            return hypotheses

        missing_raw = review_payload.get("missing", [])
        redundant_raw = review_payload.get("redundant", [])

        missing_valid = self._validate_hypotheses(missing_raw if isinstance(missing_raw, list) else [])
        redundant_set = {
            text.strip() for text in redundant_raw if isinstance(text, str) and text.strip()
        }

        merged = list(hypotheses) + missing_valid
        if redundant_set:
            merged = [h for h in merged if str(h.get("hypothesis", "")).strip() not in redundant_set]

        return merged

    def _extract_hypothesis_list(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict):
            raw = payload.get("hypotheses", [])
            return raw if isinstance(raw, list) else []
        if isinstance(payload, list):
            return payload
        return []

    def _validate_hypotheses(self, raw_hypotheses: list[Any]) -> list[dict[str, Any]]:
        valid: list[dict[str, Any]] = []

        for idx, item in enumerate(raw_hypotheses):
            if not isinstance(item, dict):
                logger.warning("Skipping non-dict hypothesis at index=%d", idx)
                continue

            missing = _REQUIRED_FIELDS - set(item.keys())
            if missing:
                logger.warning("Skipping hypothesis missing fields=%s", sorted(missing))
                continue

            inj = item.get("injection_point")
            if not isinstance(inj, dict):
                logger.warning("Skipping hypothesis with non-dict injection_point")
                continue
            inj_missing = _REQUIRED_INJECTION_POINT_FIELDS - set(inj.keys())
            if inj_missing:
                logger.warning("Skipping hypothesis missing injection_point fields=%s", sorted(inj_missing))
                continue

            try:
                parsed = HypothesisSchema.model_validate(item)
            except ValidationError as exc:
                logger.warning("Skipping invalid hypothesis due to schema error: %s", exc)
                continue

            valid.append(parsed.model_dump())
        
        category_counts: dict[str, int] = {}
        for h in valid:
            category = str(h.get("owasp_category", "unknown"))
            category_counts[category] = category_counts.get(category, 0) + 1

        for category, count in category_counts.items():
            if count > 4:
                logger.warning("Hypothesis category over-concentration category=%s count=%d", category, count)
        if category_counts:
            logger.info("Validated hypothesis category distribution: %s", category_counts)

        return valid

    def _deduplicate(self, hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: dict[tuple[str, str, str], dict[str, Any]] = {}

        for hyp in hypotheses:
            injection_point = hyp.get("injection_point", {})
            key = (
                str(injection_point.get("url", "")).strip().lower(),
                str(injection_point.get("param_name", "")).strip().lower(),
                str(hyp.get("owasp_category", "")).strip(),
            )
            existing = deduped.get(key)
            if existing is None or int(hyp.get("confidence", 0)) > int(existing.get("confidence", 0)):
                deduped[key] = hyp

        return list(deduped.values())

    def _to_node(self, hypothesis_dict: dict[str, Any]) -> Node:
        confidence = max(0, min(100, int(hypothesis_dict.get("confidence", 0)))) / 100.0
        token_est = estimate_tokens(json.dumps(hypothesis_dict, sort_keys=True))

        return Node(
            id=str(uuid.uuid4()),
            type=NodeType.HYPOTHESIS,
            content=hypothesis_dict.get("hypothesis", ""),
            depth=0,
            confidence=confidence,
            token_estimate=token_est,
            compressed_summary=hypothesis_dict,
        )
