from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4


class NodeType(str, Enum):
    HYPOTHESIS = "hypothesis"
    PROBE = "probe"
    OBSERVATION = "observation"
    FINDING = "finding"
    DEAD_END = "dead_end"


class EdgeType(str, Enum):
    GENERATED = "generated"
    RESPONDED = "responded"
    CONFIRMED = "confirmed"
    SPAWNED = "spawned"
    DERIVED = "derived"


NODE_COLORS: dict[NodeType, str] = {
    NodeType.HYPOTHESIS: "#f59e0b",
    NodeType.PROBE: "#a855f7",
    NodeType.OBSERVATION: "#3b82f6",
    NodeType.FINDING: "#22c55e",
    NodeType.DEAD_END: "#6b7280",
}


@dataclass
class Node:
    id: str
    type: NodeType
    content: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    confidence: float = 0.5
    token_estimate: int = 0
    compressed_summary: dict[str, Any] | None = None
    compressed_tokens: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "content": self.content,
            "data": self.data,
            "depth": self.depth,
            "confidence": self.confidence,
            "token_estimate": self.token_estimate,
            "compressed_summary": self.compressed_summary,
            "compressed_tokens": self.compressed_tokens,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()


@dataclass
class Edge:
    source_id: str
    target_id: str
    type: EdgeType

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.type.value,
        }


@dataclass
class AttackGraph:
    graph_id: str = field(default_factory=lambda: str(uuid4()))
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    frontier: list[str] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node
        if node.type == NodeType.HYPOTHESIS and node.id not in self.frontier:
            self.frontier.append(node.id)

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def update_node_confidence(self, node_id: str, confidence: float) -> None:
        if node_id in self.nodes:
            self.nodes[node_id].confidence = max(0.0, min(1.0, float(confidence)))

    def get_active_hypotheses(self) -> list[Node]:
        return [
            n
            for n in self.nodes.values()
            if n.type == NodeType.HYPOTHESIS and n.id in self.frontier
        ]

    def get_findings(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.type == NodeType.FINDING]

    def resolve_hypothesis(self, node_id: str, resolution_type: NodeType) -> None:
        if resolution_type not in (NodeType.FINDING, NodeType.DEAD_END):
            raise ValueError("Hypothesis can only resolve to FINDING or DEAD_END")
        if node_id not in self.nodes:
            raise KeyError(f"Node not found: {node_id}")
        self.nodes[node_id].type = resolution_type
        self.frontier = [nid for nid in self.frontier if nid != node_id]

    def get_path_to_root(self, node_id: str) -> list[Node]:
        if node_id not in self.nodes:
            return []

        visited: set[str] = set()
        path_ids: list[str] = []
        current = node_id

        while current in self.nodes and current not in visited:
            visited.add(current)
            path_ids.append(current)
            parent = next((e.source_id for e in self.edges if e.target_id == current), None)
            if parent is None:
                break
            current = parent

        path_ids.reverse()
        return [self.nodes[nid] for nid in path_ids if nid in self.nodes]

    def mark_compressed(self, node_id: str, summary: dict[str, Any], compressed_tokens: int) -> None:
        if node_id not in self.nodes:
            raise KeyError(f"Node not found: {node_id}")
        if compressed_tokens < 0:
            raise ValueError("compressed_tokens must be non-negative")
        node = self.nodes[node_id]
        node.compressed_summary = summary
        node.compressed_tokens = compressed_tokens

    def token_cost(self) -> int:
        total = 0
        for node in self.nodes.values():
            if node.compressed_tokens is not None:
                total += node.compressed_tokens
            else:
                total += node.token_estimate
        return total

    def compressible_nodes(self) -> list[Node]:
        return [
            n
            for n in self.nodes.values()
            if n.type != NodeType.FINDING and n.compressed_tokens is None
        ]

    def stats(self) -> dict[str, Any]:
        counts = Counter(n.type.value for n in self.nodes.values())
        return {
            "graph_id": self.graph_id,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "frontier_count": len(self.frontier),
            "token_cost": self.token_cost(),
            "type_distribution": dict(counts),
        }

    def to_d3(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "stats": self.stats(),
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type.value,
                    "color": NODE_COLORS.get(n.type, "#111827"),
                    "depth": n.depth,
                    "confidence": n.confidence,
                }
                for n in self.nodes.values()
            ],
            "links": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.type.value,
                }
                for e in self.edges
            ],
        }

    @classmethod
    def from_db(cls, data: dict[str, Any]) -> "AttackGraph":
        meta = data.get("meta", {}) if isinstance(data, dict) else {}
        graph = cls(graph_id=meta.get("graph_id", str(uuid4())))

        # Frontier is rebuilt via add_node(); correctness depends on persisted
        # terminal node types in DB. Resolved hypotheses must be stored as
        # FINDING/DEAD_END (not HYPOTHESIS), which keeps only unresolved
        # hypotheses on the restored frontier.

        for raw in data.get("nodes", []):
            node = Node(
                id=raw["id"],
                type=NodeType(raw["type"]),
                content=raw.get("content", ""),
                data=raw.get("data", {}),
                depth=raw.get("depth", 0),
                confidence=raw.get("confidence", 0.5),
                token_estimate=raw.get("token_estimate", 0),
                compressed_summary=raw.get("compressed_summary"),
                compressed_tokens=raw.get("compressed_tokens"),
            )
            graph.add_node(node)

        for raw in data.get("edges", []):
            graph.add_edge(
                Edge(
                    source_id=raw["source_id"],
                    target_id=raw["target_id"],
                    type=EdgeType(raw["type"]),
                )
            )

        return graph
