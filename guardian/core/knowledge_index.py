"""
guardian/core/knowledge_index.py
"""

import logging
import os
import re
from difflib import get_close_matches
from pathlib import Path
from typing import Optional

from guardian.core.config import settings

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Category-to-file mapping table (FIX 04)
# Verified against the PayloadsAllTheThings repo structure.
# Keys are lowercase OWASP category IDs and common vulnerability name keywords.
# Values are filenames (basenames only) as they appear in the repo.
# ──────────────────────────────────────────────────────────────────────────────
OWASP_TO_FILES: dict[str, list[str]] = {
    # A01 — Broken Access Control
    "a01:2023":         ["IDOR.md", "Path Traversal.md", "File Inclusion.md"],
    "broken access":    ["IDOR.md", "Path Traversal.md"],
    "idor":             ["IDOR.md"],
    "path traversal":   ["Path Traversal.md"],
    "lfi":              ["File Inclusion.md"],
    "rfi":              ["File Inclusion.md"],

    # A02 — Cryptographic Failures
    "a02:2023":         ["CORS Misconfiguration.md"],
    "cryptographic":    [],
    "tls":              ["CORS Misconfiguration.md"],
    "ssl":              ["CORS Misconfiguration.md"],
    "sensitive data":   ["CORS Misconfiguration.md"],

    # A03 — Injection
    "a03:2023":         ["SQL Injection.md", "XSS Injection.md", "Command Injection.md",
                         "SSTI - Server Side Template Injection.md", "XXE Injection.md",
                         "LDAP Injection.md", "NoSQL Injection.md"],
    "sql injection":    ["SQL Injection.md"],
    "sqli":             ["SQL Injection.md"],
    "xss":              ["XSS Injection.md"],
    "cross-site scripting": ["XSS Injection.md"],
    "command injection": ["Command Injection.md"],
    "rce":              ["Command Injection.md"],
    "remote code":      ["Command Injection.md"],
    "ssti":             ["SSTI - Server Side Template Injection.md"],
    "template injection": ["SSTI - Server Side Template Injection.md"],
    "xxe":              ["XXE Injection.md"],
    "xml injection":    ["XXE Injection.md"],
    "ldap injection":   ["LDAP Injection.md"],
    "nosql":            ["NoSQL Injection.md"],

    # A04 — Insecure Design
    "a04:2023":         ["HTTP Parameter Pollution.md"],
    "business logic":   ["HTTP Parameter Pollution.md"],

    # A05 — Security Misconfiguration
    "a05:2023":         ["CORS Misconfiguration.md", "HTTP Parameter Pollution.md"],
    "cors":             ["CORS Misconfiguration.md"],
    "misconfiguration": ["CORS Misconfiguration.md"],

    # A06 — Vulnerable Components
    "a06:2023":         [],

    # A07 — Authentication Failures
    "a07:2023":         ["Authentication Bypass.md", "JWT Attacks.md",
                         "OAuth Misconfiguration.md"],
    "authentication":   ["Authentication Bypass.md"],
    "auth bypass":      ["Authentication Bypass.md"],
    "jwt":              ["JWT Attacks.md"],
    "session":          ["Authentication Bypass.md"],
    "oauth":            ["OAuth Misconfiguration.md"],

    # A08 — Software Integrity Failures
    "a08:2023":         ["Insecure Deserialization.md"],
    "deserialization":  ["Insecure Deserialization.md"],
    "serialization":    ["Insecure Deserialization.md"],

    # A09 — Logging Failures
    "a09:2023":         ["Log Injection.md"],
    "log injection":    ["Log Injection.md"],

    # A10 — SSRF
    "a10:2023":         ["SSRF - Server-Side Request Forgery.md"],
    "ssrf":             ["SSRF - Server-Side Request Forgery.md"],
    "server-side request": ["SSRF - Server-Side Request Forgery.md"],

    # Additional common types
    "open redirect":    ["Open Redirect.md"],
    "crlf":             ["CRLF Injection.md"],
    "csrf":             ["CSRF Injection.md"],
    "clickjacking":     ["Clickjacking.md"],
    "file upload":      ["File Upload.md"],
    "insecure upload":  ["File Upload.md"],
    "subdomain takeover": ["Subdomain Takeover.md"],
}

# Keywords that indicate a markdown section contains payload content
_PAYLOAD_SECTION_KEYWORDS = frozenset([
    "payload", "example", "exploit", "bypass", "filter", "evasion",
    "injection", "attack", "poc", "proof", "cheat", "cheatsheet",
    "technique", "vector", "method", "trick", "waf", "obfuscat",
])

# Approximate chars-per-token ratio for token budget estimation
_CHARS_PER_TOKEN = 4


# ──────────────────────────────────────────────────────────────────────────────
# File index
# ──────────────────────────────────────────────────────────────────────────────
class KnowledgeIndex:
    """
    Singleton-style index of all .md files under PAYLOADS_REPO_PATH.
    Built once at first access; can be force-rebuilt via reload().
    """

    def __init__(self) -> None:
        self._filename_index: dict[str, str] = {}   # basename.lower() → absolute path
        self._all_basenames: list[str] = []          # for fuzzy matching
        self._built = False

    def build(self, repo_path: str | None = None) -> None:
        """Walk the repo and index every .md file."""
        path = repo_path or settings.PAYLOADS_REPO_PATH
        root = Path(path)

        if not root.exists():
            logger.warning(
                "PayloadsAllTheThings repo not found at %s. "
                "RAG will operate without knowledge retrieval.",
                path,
            )
            self._built = True
            return

        count = 0
        for fpath in root.rglob("*.md"):
            key = fpath.name.lower()
            # If duplicate basenames exist, prefer shallower paths
            existing = self._filename_index.get(key)
            if existing is None or len(fpath.parts) < len(Path(existing).parts):
                self._filename_index[key] = str(fpath)
                count += 1

        self._all_basenames = list(self._filename_index.keys())
        self._built = True
        logger.info(
            "Knowledge index built: %d .md files indexed from %s", count, path
        )

    def _ensure_built(self) -> None:
        if not self._built:
            self.build()

    def reload(self) -> None:
        """Force a full re-index (call if the repo is updated at runtime)."""
        self._filename_index.clear()
        self._all_basenames.clear()
        self._built = False
        self.build()

    def get_file_path(self, filename: str) -> str | None:
        """
        Look up a filename. Steps:
          1. Exact match (case-insensitive)
          2. Fuzzy match via difflib at threshold 0.75
          3. Return None if no match found
        """
        self._ensure_built()
        if not filename:
            return None

        key = filename.strip().lower()

        # Exact
        exact = self._filename_index.get(key)
        if exact:
            return exact

        # Fuzzy
        matches = get_close_matches(key, self._all_basenames, n=1, cutoff=0.75)
        if matches:
            resolved = self._filename_index[matches[0]]
            logger.debug(
                "Fuzzy filename match: '%s' → '%s'", filename, matches[0]
            )
            return resolved

        logger.warning("Knowledge file not found: '%s'", filename)
        return None

    def files_for_vulnerability(
        self,
        owasp_category: str,
        vuln_name: str,
    ) -> list[str]:
        """
        Return a list of absolute file paths for a given vulnerability using
        the OWASP_TO_FILES mapping table. Falls back to fuzzy title search
        against all indexed filenames if no mapping entry exists.
        """
        self._ensure_built()
        candidates: list[str] = []

        # Try OWASP category key first
        cat_key = owasp_category.lower().strip()
        for fname in OWASP_TO_FILES.get(cat_key, []):
            path = self.get_file_path(fname)
            if path:
                candidates.append(path)

        # Try vulnerability name keyword matching
        vuln_lower = vuln_name.lower()
        for keyword, fnames in OWASP_TO_FILES.items():
            if keyword in vuln_lower or vuln_lower in keyword:
                for fname in fnames:
                    path = self.get_file_path(fname)
                    if path and path not in candidates:
                        candidates.append(path)

        # Fallback: fuzzy search against all indexed basenames
        if not candidates:
            words = re.findall(r"[a-z]+", vuln_lower)
            for word in words:
                if len(word) < 4:
                    continue
                matches = get_close_matches(
                    word, self._all_basenames, n=2, cutoff=0.6
                )
                for m in matches:
                    path = self._filename_index[m]
                    if path not in candidates:
                        candidates.append(path)

        return candidates[:3]  # Cap at 3 files per vulnerability

    def list_all_filenames(self) -> list[str]:
        """Return all indexed basenames (original case)."""
        self._ensure_built()
        return [Path(p).name for p in self._filename_index.values()]


# ──────────────────────────────────────────────────────────────────────────────
# Section-aware content extraction  (FIX 05)
# ──────────────────────────────────────────────────────────────────────────────
def parse_knowledge_file(
    file_path: str,
    token_budget: int = 3500,
) -> str:
    """
    Extract the most payload-relevant content from a markdown file.

    Strategy:
      1. Parse the file into sections (## / ### headings).
      2. Score each section: heading contains payload-relevant keyword → score 2;
         body contains keyword → score 1.
      3. Sort sections by score descending, then take sections greedily until
         the token budget is exhausted.
      4. Always prepend the first section (file intro) for context.
      5. Fall back to the entire file (truncated) if no sections are found.

    Returns a string under the token budget.
    """
    try:
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        logger.error("Cannot read knowledge file %s: %s", file_path, exc)
        return ""

    # Split into sections on ## or ### headings
    section_pattern = re.compile(r"^#{1,3}\s+.+", re.MULTILINE)
    boundaries = [m.start() for m in section_pattern.finditer(raw)]

    if not boundaries:
        # No headings — return token-budget-truncated raw content
        budget_chars = token_budget * _CHARS_PER_TOKEN
        return raw[:budget_chars]

    # Build section list: (heading_text, body_text)
    sections: list[tuple[str, str]] = []
    for i, start in enumerate(boundaries):
        end = boundaries[i + 1] if i + 1 < len(boundaries) else len(raw)
        block = raw[start:end]
        lines = block.splitlines()
        heading = lines[0].lstrip("#").strip()
        body = "\n".join(lines[1:]).strip()
        sections.append((heading, body))

    # Score sections
    def score_section(heading: str, body: str) -> int:
        h_lower = heading.lower()
        b_lower = body.lower()
        s = 0
        for kw in _PAYLOAD_SECTION_KEYWORDS:
            if kw in h_lower:
                s += 2
            elif kw in b_lower:
                s += 1
        return s

    scored = [
        (score_section(h, b), h, b)
        for h, b in sections
    ]

    # Always include intro (first section regardless of score)
    intro_heading, intro_body = sections[0]
    intro_text = f"## {intro_heading}\n{intro_body}\n\n"
    used_chars = len(intro_text)
    selected_parts = [intro_text]

    # Take remaining sections by score descending
    remaining = sorted(scored[1:], key=lambda x: x[0], reverse=True)
    for _, heading, body in remaining:
        block = f"## {heading}\n{body}\n\n"
        if used_chars + len(block) > token_budget * _CHARS_PER_TOKEN:
            # Try a truncated version if it has high relevance
            available = token_budget * _CHARS_PER_TOKEN - used_chars
            if available > 200:
                selected_parts.append(block[:available])
            break
        selected_parts.append(block)
        used_chars += len(block)

    result = "".join(selected_parts)
    estimated_tokens = len(result) // _CHARS_PER_TOKEN
    logger.debug(
        "Knowledge extraction: file=%s sections=%d tokens≈%d",
        Path(file_path).name,
        len(selected_parts),
        estimated_tokens,
    )
    return result


def estimate_tokens(text: str) -> int:
    """Rough token count estimate: 1 token ≈ 4 characters."""
    return len(text) // _CHARS_PER_TOKEN


# Module-level singleton — import this everywhere
knowledge_index = KnowledgeIndex()
