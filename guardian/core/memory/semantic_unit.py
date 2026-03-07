from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from math import log2


@dataclass
class SemanticUnit:
    content: str
    source: str
    token_count: int
    entropy: float
    compressed_from: str | None = None
    irreducible_facts: list[str] = field(default_factory=list)

    @classmethod
    def from_raw(cls, raw: str, source: str) -> "SemanticUnit":
        text = raw or ""
        entropy = cls._normalized_entropy(text)
        return cls(
            content=text,
            source=source,
            token_count=len(text) // 4,
            entropy=entropy,
        )

    @staticmethod
    def _normalized_entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        total = len(text)
        if total == 0:
            return 0.0
        entropy = -sum((c / total) * log2(c / total) for c in counts.values())
        max_entropy = log2(max(len(counts), 1))
        if max_entropy == 0:
            return 0.0
        return entropy / max_entropy

    @property
    def compression_ratio(self) -> float:
        if not self.compressed_from:
            return 1.0
        original = max(len(self.compressed_from), 1)
        return len(self.content) / original

    def prompt_repr(self) -> str:
        lines: list[str] = []
        if self.irreducible_facts:
            lines.append("Facts:")
            lines.extend(f"- {fact}" for fact in self.irreducible_facts)
            lines.append("")
        lines.append(self.content)
        return "\n".join(lines).strip()

    @property
    def is_high_entropy(self) -> bool:
        return self.entropy >= 0.7
