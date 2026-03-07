from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class TokenLedger:
    total: int
    used: int = 0
    _by_component: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def charge(self, amount: int, component: str = "general") -> bool:
        if amount < 0:
            raise ValueError("amount must be non-negative")
        if self.used + amount > self.total:
            return False
        self.used += amount
        self._by_component[component] += amount
        return True

    def remaining(self) -> int:
        return self.total - self.used

    def utilization(self) -> float:
        if self.total <= 0:
            return 1.0
        return self.used / self.total

    def is_critical(self, threshold: float = 0.9) -> bool:
        return self.utilization() >= threshold

    def snapshot(self) -> dict:
        return {
            "total": self.total,
            "used": self.used,
            "remaining": self.remaining(),
            "utilization": self.utilization(),
            "by_component": dict(self._by_component),
        }
