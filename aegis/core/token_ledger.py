from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

class SubBudget:
    def __init__(self, parent: "TokenLedger", total: int, component: str = "general") -> None:
        self.parent = parent
        self.total = max(int(total), 0)
        self.used = 0
        self.component = component
        self._released = False
        self._spent_by_component: dict[str, int] = defaultdict(int)

    def charge(self, amount: int, component: str = "general") -> bool:
        if self._released:
            return False
        if amount < 0:
            raise ValueError("amount must be non-negative")
        if self.used + amount > self.total:
            return False

        parent_component = f"{self.component}:{component}" if component else self.component
        if not self.parent.charge(amount, component=parent_component):
            return False

        self.used += amount
        self._spent_by_component[parent_component] += amount
        return True

    def remaining(self) -> int:
        return self.total - self.used

    def utilization(self) -> float:
        if self.total <= 0:
            return 1.0
        return self.used / self.total

    def is_critical(self, threshold: float = 0.9) -> bool:
        return self.utilization() >= threshold

    def release(self) -> None:
        if self._released:
            return
        if self.used > 0:
            self.parent.used = max(0, self.parent.used - self.used)
            for component, amount in self._spent_by_component.items():
                self.parent._by_component[component] = max(0, self.parent._by_component.get(component, 0) - amount)
                if self.parent._by_component[component] == 0:
                    self.parent._by_component.pop(component, None)
        self._released = True

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
    
    def allocate_sub_budget(self, amount: int, component: str = "general") -> SubBudget:
        alloc = max(0, min(int(amount), self.remaining()))
        return SubBudget(parent=self, total=alloc, component=component)

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
    
    def render_breakdown(self) -> str:
        total = max(int(self.total), 1)
        used_pct = (self.used / total) * 100.0
        lines = [f"Total: {self.used} / {self.total} ({used_pct:.1f}%)", "By component:"]

        total_used = max(self.used, 1)
        for component, tokens in sorted(self._by_component.items(), key=lambda kv: kv[1], reverse=True):
            pct = (tokens / total_used) * 100.0
            lines.append(f"  - {component}: {tokens} tokens ({pct:.1f}%)")

        lines.append(f"Remaining: {self.remaining()} tokens")
        return "\n".join(lines)
