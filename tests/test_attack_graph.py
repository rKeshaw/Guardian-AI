from guardian.core.graph.attack_graph import AttackGraph, Edge, EdgeType, Node, NodeType


class TestAttackGraph:
    def test_add_hypothesis_goes_to_frontier(self):
        graph = AttackGraph()
        node = Node(id="A", type=NodeType.HYPOTHESIS, content="hypothesis")
        graph.add_node(node)

        assert len(graph.frontier) == 1
        assert graph.frontier[0] == node.id

    def test_add_finding_not_on_frontier(self):
        graph = AttackGraph()
        node = Node(id="F", type=NodeType.FINDING, content="finding")
        graph.add_node(node)

        assert len(graph.frontier) == 0

    def test_resolve_hypothesis_to_finding(self):
        graph = AttackGraph()
        node = Node(id="A", type=NodeType.HYPOTHESIS, content="hypothesis")
        graph.add_node(node)

        graph.resolve_hypothesis(node.id, NodeType.FINDING)

        assert node.id not in graph.frontier
        assert graph.nodes[node.id].type == NodeType.FINDING

    def test_resolve_hypothesis_to_dead_end(self):
        graph = AttackGraph()
        node = Node(id="A", type=NodeType.HYPOTHESIS, content="hypothesis")
        graph.add_node(node)

        graph.resolve_hypothesis(node.id, NodeType.DEAD_END)

        assert node.id not in graph.frontier
        assert graph.nodes[node.id].type == NodeType.DEAD_END

    def test_get_path_to_root_single_chain(self):
        graph = AttackGraph()
        node_a = Node(id="A", type=NodeType.HYPOTHESIS, content="root")
        node_b = Node(id="B", type=NodeType.OBSERVATION, content="obs")
        node_c = Node(id="C", type=NodeType.FINDING, content="finding")

        graph.add_node(node_a)
        graph.add_node(node_b)
        graph.add_node(node_c)
        graph.add_edge(Edge(source_id="A", target_id="B", type=EdgeType.GENERATED))
        graph.add_edge(Edge(source_id="B", target_id="C", type=EdgeType.CONFIRMED))

        path = graph.get_path_to_root(node_c.id)

        assert [n.id for n in path] == ["A", "B", "C"]

    def test_get_path_to_root_prevents_infinite_loop(self):
        graph = AttackGraph()
        node_a = Node(id="A", type=NodeType.HYPOTHESIS, content="A")
        node_b = Node(id="B", type=NodeType.OBSERVATION, content="B")

        graph.add_node(node_a)
        graph.add_node(node_b)
        graph.add_edge(Edge(source_id="A", target_id="B", type=EdgeType.GENERATED))
        graph.add_edge(Edge(source_id="B", target_id="A", type=EdgeType.GENERATED))

        path = graph.get_path_to_root("A")

        assert len(path) <= 2

    def test_token_cost_excludes_compressed_nodes(self):
        graph = AttackGraph()
        node_1 = Node(id="N1", type=NodeType.OBSERVATION, content="one", token_estimate=100)
        node_2 = Node(id="N2", type=NodeType.OBSERVATION, content="two", token_estimate=100)

        graph.add_node(node_1)
        graph.add_node(node_2)
        graph.mark_compressed(node_1.id, {}, 10)

        assert graph.token_cost() == 110

    def test_compressible_nodes_excludes_findings(self):
        graph = AttackGraph()
        finding = Node(id="F", type=NodeType.FINDING, content="f", token_estimate=500)
        observation = Node(id="O", type=NodeType.OBSERVATION, content="o", token_estimate=200)

        graph.add_node(finding)
        graph.add_node(observation)

        compressible = graph.compressible_nodes()

        assert [n.id for n in compressible] == ["O"]

    def test_stats_type_distribution(self):
        graph = AttackGraph()
        graph.add_node(Node(id="H1", type=NodeType.HYPOTHESIS, content="h1"))
        graph.add_node(Node(id="H2", type=NodeType.HYPOTHESIS, content="h2"))
        graph.add_node(Node(id="O1", type=NodeType.OBSERVATION, content="o1"))
        graph.add_node(Node(id="F1", type=NodeType.FINDING, content="f1"))

        dist = graph.stats()["type_distribution"]

        assert dist == {"hypothesis": 2, "observation": 1, "finding": 1}

    def test_to_d3_structure(self):
        graph = AttackGraph()
        graph.add_node(Node(id="H", type=NodeType.HYPOTHESIS, content="h"))

        data = graph.to_d3()

        assert set(data.keys()) == {"nodes", "links", "graph_id", "stats"}
        for node in data["nodes"]:
            assert {"id", "type", "color", "depth", "confidence"}.issubset(node.keys())

    def test_from_db_restores_frontier(self):
        graph = AttackGraph()
        graph.add_node(Node(id="H1", type=NodeType.HYPOTHESIS, content="h1"))
        graph.add_node(Node(id="H2", type=NodeType.HYPOTHESIS, content="h2"))
        graph.add_node(Node(id="F1", type=NodeType.FINDING, content="f1"))

        data = {
            "meta": {"graph_id": graph.graph_id},
            "nodes": [n.model_dump() if hasattr(n, "model_dump") else n.__dict__ for n in graph.nodes.values()],
            "edges": [e.model_dump() if hasattr(e, "model_dump") else e.__dict__ for e in graph.edges],
        }

        restored = AttackGraph.from_db(data)

        assert len(restored.frontier) == 2
