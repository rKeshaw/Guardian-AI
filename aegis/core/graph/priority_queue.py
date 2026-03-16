from __future__ import annotations

import heapq
from typing import Iterable

from aegis.core.graph.attack_graph import Node


class HypothesisPriorityQueue:
    def __init__(self, nodes: Iterable[Node] | None = None) -> None:
        self._heap: list[tuple[float, str, Node]] = []
        self._ids: set[str] = set()
        if nodes:
            for node in nodes:
                self.push(node)

    @staticmethod
    def _score(node: Node) -> float:
        impact = float(node.data.get("owasp_impact", 5)) / 10.0
        depth_decay = 1.0 / (1.0 + node.depth * 0.15)
        confidence = float(node.confidence)
        return confidence * 0.45 + impact * 0.40 + depth_decay * 0.15

    def push(self, node: Node) -> None:
        if node.id in self._ids:
            return
        score = self._score(node)
        heapq.heappush(self._heap, (-score, node.id, node))
        self._ids.add(node.id)

    def pop(self) -> Node | None:
        while self._heap:
            _, node_id, node = heapq.heappop(self._heap)
            if node_id in self._ids:
                self._ids.remove(node_id)
                return node
        return None

    def size(self) -> int:
        return len(self._ids)

    def contains(self, node_id: str) -> bool:
        return node_id in self._ids
