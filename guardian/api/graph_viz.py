from __future__ import annotations

from guardian.core.graph.attack_graph import AttackGraph


def build_graph_response(graph: AttackGraph) -> dict:
    payload = graph.to_d3()
    reasoning_chains: list[dict] = []

    for finding in graph.get_findings():
        chain_nodes = graph.get_path_to_root(finding.id)
        reasoning_chains.append(
            {
                "finding_id": finding.id,
                "finding_hypothesis": finding.data.get("hypothesis", finding.content),
                "chain": [
                    {
                        "id": node.id,
                        "type": node.type.value,
                        "label": node.content or node.data.get("hypothesis") or node.data.get("probe") or node.type.value,
                    }
                    for node in chain_nodes
                ],
            }
        )

    payload["reasoning_chains"] = reasoning_chains
    return payload
