from __future__ import annotations

import re
from dataclasses import dataclass
from html import unescape
from urllib.parse import unquote

from aegis.core.ai_client import estimate_tokens
from aegis.core.memory.semantic_unit import SemanticUnit


JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")
UNIX_PATH_RE = re.compile(r"(/(?:[\w.-]+/)*[\w.-]+)")


@dataclass
class ComprehensionResult:
    content: str
    irreducible_facts: list[str]


class Comprehender:
    def compress(self, content: str, source: str, probe_sent: str | None = None) -> dict:
        text = content or ""
        cleaned = self._strip_boilerplate(text)
        facts = self._extract_facts(text, probe_sent=probe_sent)
        return {
            "source": source,
            "content": cleaned,
            "irreducible_facts": facts,
        }

    async def compress_async(
        self,
        content: str,
        content_type: str,
        probe_sent: str | None,
        ai_client,
        token_ledger,
    ) -> SemanticUnit:
        compressed = self.compress(content, content_type, probe_sent=probe_sent)
        unit = SemanticUnit.from_raw(compressed["content"], content_type)
        unit.irreducible_facts = list(compressed["irreducible_facts"])

        try:
            token_ledger.charge(estimate_tokens(content), component="comprehender")
        except Exception:
            pass

        return unit

    async def compress_episode(self, turns: list[dict], confirmed_facts: set[str], ai_client, token_ledger) -> SemanticUnit:
        merged = "\n".join(str(t) for t in turns)
        unit = SemanticUnit.from_raw(self._strip_boilerplate(merged), "episode")
        unit.irreducible_facts = [f for f in sorted(confirmed_facts)[:20]]

        try:
            token_ledger.charge(estimate_tokens(merged), component="comprehender")
        except Exception:
            pass

        return unit

    async def is_near_duplicate(self, probe: str, tried_probes: set[str]) -> bool:
        normalized = self._normalize_probe(probe)
        normalized_tried = {self._normalize_probe(p) for p in tried_probes}
        return normalized in normalized_tried

    def _extract_facts(self, text: str, probe_sent: str | None = None) -> list[str]:
        facts: list[str] = []
        lower = text.lower()

        if "you have an error in your sql syntax" in lower or "mysql" in lower:
            facts.append("mysql_error: detected SQL parser error signature")

        if re.search(r"uid=\d+\([^)]*\)", text):
            facts.append("uid_output: command execution style uid/gid output detected")

        for path in UNIX_PATH_RE.findall(text):
            if path.startswith("/") and len(path) > 2 and "/" in path[1:]:
                facts.append(f"unix_path: {path}")
                break

        if probe_sent:
            probe_norm = self._normalize_probe(probe_sent)
            text_norm = self._normalize_probe(text)
            if probe_norm and probe_norm in text_norm:
                facts.append("reflection: probe reflected in server response")

        token = JWT_RE.search(text)
        if token:
            facts.append(f"jwt_token: {token.group(0)}")

        return facts

    def _strip_boilerplate(self, text: str) -> str:
        cleaned = unescape(text)
        cleaned = re.sub(r"<nav[\s\S]*?</nav>", " ", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"<footer[\s\S]*?</footer>", " ", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"<[^>]+>", " ", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()

        if len(cleaned) <= 500:
            return cleaned

        marker_match = re.search(r"invalid query|error|exception|sql|warning", cleaned, flags=re.IGNORECASE)
        if marker_match:
            center = marker_match.start()
            start = max(center - 220, 0)
            end = min(center + 220, len(cleaned))
            return cleaned[start:end].strip()

        signal_patterns = [r"invalid query", r"error", r"exception", r"sql", r"warning"]
        parts = re.split(r"(?<=[.!?])\s+", cleaned)
        signal = [p for p in parts if any(re.search(pat, p, flags=re.IGNORECASE) for pat in signal_patterns)]
        if signal:
            merged = " | ".join(signal)
            return merged[:480]

        return cleaned[:480]

    def _normalize_probe(self, probe: str) -> str:
        decoded = unquote(probe or "")
        lowered = decoded.lower()
        lowered = re.sub(r"\s+", " ", lowered).strip()

        # Canonicalize path traversal encodings and separators
        lowered = lowered.replace("%2e", ".").replace("%2f", "/").replace("%5c", "\\")
        lowered = lowered.replace("..\\", "../")
        lowered = lowered.replace("..%2f", "../")
        lowered = lowered.replace("%2e%2e/", "../")
        def _collapse_traversal(match: re.Match) -> str:
            _ = match.group(0)
            return "[N]../"

        lowered = re.sub(r"(?:\.\./|\.\.\\)+", _collapse_traversal, lowered)

        # SQLi boolean-based canonicalization
        lowered = re.sub(
            r"'\s*or\s*\d+\s*=\s*\d+\s*(?:--|#)?",
            "' or n=n--",
            lowered,
            flags=re.IGNORECASE,
        )

        # SQLi union select canonicalization by removing variable column count
        lowered = re.sub(
            r"union\s+select\s+[\d\s,]+",
            "union select ?",
            lowered,
            flags=re.IGNORECASE,
        )

        # XSS canonicalization by vector type
        if re.search(r"<\s*script\b[\s\S]*?<\s*/\s*script(?:\s+[^>]*)?>", lowered, flags=re.IGNORECASE):
            lowered = "xss_script_tag"
        elif re.search(r"<\s*img\b[^>]*onerror\s*=", lowered, flags=re.IGNORECASE):
            lowered = "xss_img_tag"
        elif "javascript:" in lowered:
            lowered = "xss_javascript_uri"

        lowered = re.sub(r"\s+", " ", lowered).strip()
        return lowered

# Module-level singleton
comprehender = Comprehender()
