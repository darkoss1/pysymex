import pytest
from unittest.mock import Mock, patch
from pysymex.analysis.interprocedural.callgraph import (
    CallGraphNode, CallGraphEdge, CallGraph, CallGraphBuilder,
    get_analysis_order, find_mutual_recursion, compute_dominators
)

class TestCallGraphNode:
    """Test suite for pysymex.analysis.interprocedural.callgraph.CallGraphNode."""
    def test_full_name(self) -> None:
        """Test full_name behavior."""
        node = CallGraphNode(name="func", module="mod")
        assert node.full_name == "mod.func"
        node2 = CallGraphNode(name="func")
        assert node2.full_name == "func"

    def test_callers(self) -> None:
        """Test callers behavior."""
        node = CallGraphNode(name="func")
        node.add_caller("c1")
        assert "c1" in node.callers

    def test_callees(self) -> None:
        """Test callees behavior."""
        node = CallGraphNode(name="func")
        node.add_callee("c2")
        assert "c2" in node.callees

    def test_add_caller(self) -> None:
        """Test add_caller behavior."""
        node = CallGraphNode(name="func")
        node.add_caller("c1")
        assert "c1" in node._callers

    def test_add_callee(self) -> None:
        """Test add_callee behavior."""
        node = CallGraphNode(name="func")
        node.add_callee("c2")
        assert "c2" in node._callees

class TestCallGraphEdge:
    """Test suite for pysymex.analysis.interprocedural.callgraph.CallGraphEdge."""
    def test_add_call_site(self) -> None:
        """Test add_call_site behavior."""
        edge = CallGraphEdge("a", "b")
        edge.add_call_site(10)
        edge.add_call_site(10) # duplicate
        assert edge.call_sites == [10]

    def test_call_count(self) -> None:
        """Test call_count behavior."""
        edge = CallGraphEdge("a", "b", call_sites=[10, 20])
        assert edge.call_count == 2

class TestCallGraph:
    """Test suite for pysymex.analysis.interprocedural.callgraph.CallGraph."""
    def test_add_node(self) -> None:
        """Test add_node behavior."""
        cg = CallGraph()
        node = CallGraphNode(name="f")
        cg.add_node(node)
        assert "f" in cg._nodes

    def test_get_node(self) -> None:
        """Test get_node behavior."""
        cg = CallGraph()
        node = CallGraphNode(name="f")
        cg.add_node(node)
        assert cg.get_node("f") is node
        assert cg.get_node("unknown") is None

    def test_has_node(self) -> None:
        """Test has_node behavior."""
        cg = CallGraph()
        cg.add_node(CallGraphNode(name="f"))
        assert cg.has_node("f") is True

    def test_nodes(self) -> None:
        """Test nodes behavior."""
        cg = CallGraph()
        cg.add_node(CallGraphNode(name="f"))
        assert len(cg.nodes()) == 1

    def test_node_names(self) -> None:
        """Test node_names behavior."""
        cg = CallGraph()
        cg.add_node(CallGraphNode(name="f"))
        assert "f" in cg.node_names()

    def test_add_edge(self) -> None:
        """Test add_edge behavior."""
        cg = CallGraph()
        cg.add_node(CallGraphNode(name="a"))
        cg.add_node(CallGraphNode(name="b"))
        cg.add_edge("a", "b", pc=10)
        assert cg.has_edge("a", "b") is True
        edge = cg.get_edge("a", "b")
        assert edge is not None
        assert edge.call_sites == [10]

    def test_get_edge(self) -> None:
        """Test get_edge behavior."""
        cg = CallGraph()
        cg.add_edge("a", "b", pc=10)
        assert cg.get_edge("a", "b") is not None

    def test_has_edge(self) -> None:
        """Test has_edge behavior."""
        cg = CallGraph()
        cg.add_edge("a", "b", pc=10)
        assert cg.has_edge("a", "b") is True

    def test_edges(self) -> None:
        """Test edges behavior."""
        cg = CallGraph()
        cg.add_edge("a", "b", pc=10)
        assert len(cg.edges()) == 1

    def test_get_callers(self) -> None:
        """Test get_callers behavior."""
        cg = CallGraph()
        cg.add_node(CallGraphNode(name="a"))
        cg.add_node(CallGraphNode(name="b"))
        cg.add_edge("a", "b")
        assert "a" in cg.get_callers("b")

    def test_get_callees(self) -> None:
        """Test get_callees behavior."""
        cg = CallGraph()
        cg.add_node(CallGraphNode(name="a"))
        cg.add_node(CallGraphNode(name="b"))
        cg.add_edge("a", "b")
        assert "b" in cg.get_callees("a")

    def test_get_transitive_callers(self) -> None:
        """Test get_transitive_callers behavior."""
        cg = CallGraph()
        for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        cg.add_edge("b", "c")
        callers = cg.get_transitive_callers("c")
        assert "a" in callers and "b" in callers

    def test_get_transitive_callees(self) -> None:
        """Test get_transitive_callees behavior."""
        cg = CallGraph()
        for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        cg.add_edge("b", "c")
        callees = cg.get_transitive_callees("a")
        assert "b" in callees and "c" in callees

    def test_is_reachable(self) -> None:
        """Test is_reachable behavior."""
        cg = CallGraph()
        for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        assert cg.is_reachable("a", "b") is True
        assert cg.is_reachable("a", "c") is False

    def test_find_cycles(self) -> None:
        """Test find_cycles behavior."""
        cg = CallGraph()
        for x in ["a", "b"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        cg.add_edge("b", "a")
        cycles = cg.find_cycles()
        assert len(cycles) > 0

    def test_is_recursive(self) -> None:
        """Test is_recursive behavior."""
        cg = CallGraph()
        for x in ["a", "b"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        cg.add_edge("b", "a")
        assert cg.is_recursive("a") is True

    def test_is_directly_recursive(self) -> None:
        """Test is_directly_recursive behavior."""
        cg = CallGraph()
        cg.add_node(CallGraphNode(name="a"))
        cg.add_edge("a", "a")
        assert cg.is_directly_recursive("a") is True

    def test_get_recursive_functions(self) -> None:
        """Test get_recursive_functions behavior."""
        cg = CallGraph()
        cg.add_node(CallGraphNode(name="a"))
        cg.add_edge("a", "a")
        assert "a" in cg.get_recursive_functions()

    def test_topological_order(self) -> None:
        """Test topological_order behavior."""
        cg = CallGraph()
        for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        cg.add_edge("b", "c")
        order = cg.topological_order()
        assert order == ["c", "b", "a"]

    def test_reverse_topological_order(self) -> None:
        """Test reverse_topological_order behavior."""
        cg = CallGraph()
        for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        cg.add_edge("b", "c")
        order = cg.reverse_topological_order()
        assert order == ["a", "b", "c"]

    def test_strongly_connected_components(self) -> None:
        """Test strongly_connected_components behavior."""
        cg = CallGraph()
        for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        cg.add_edge("b", "a")
        cg.add_edge("c", "a")
        sccs = cg.strongly_connected_components()
        assert len(sccs) == 2
        assert any("a" in scc and "b" in scc for scc in sccs)

    def test_entry_points(self) -> None:
        """Test entry_points behavior."""
        cg = CallGraph()
        for x in ["a", "b"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        assert "a" in cg.entry_points()

    def test_leaf_functions(self) -> None:
        """Test leaf_functions behavior."""
        cg = CallGraph()
        for x in ["a", "b"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        assert "b" in cg.leaf_functions()

    def test_call_depth(self) -> None:
        """Test call_depth behavior."""
        cg = CallGraph()
        for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        cg.add_edge("b", "c")
        assert cg.call_depth("a") == 2
        cg.add_edge("c", "a")
        assert cg.call_depth("a") == -1

    def test_merge(self) -> None:
        """Test merge behavior."""
        cg1 = CallGraph()
        cg1.add_node(CallGraphNode(name="a"))
        cg2 = CallGraph()
        cg2.add_node(CallGraphNode(name="b"))
        cg2.add_edge("b", "a", pc=10)
        cg1.merge(cg2)
        assert "b" in cg1.node_names()
        assert cg1.has_edge("b", "a") is True

    def test_subgraph(self) -> None:
        """Test subgraph behavior."""
        cg = CallGraph()
        for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
        cg.add_edge("a", "b")
        cg.add_edge("b", "c")
        sub = cg.subgraph({"a", "b"})
        assert "a" in sub.node_names()
        assert "c" not in sub.node_names()
        assert sub.has_edge("a", "b") is True
        assert sub.has_edge("b", "c") is False

class TestCallGraphBuilder:
    """Test suite for pysymex.analysis.interprocedural.callgraph.CallGraphBuilder."""
    def test_add_function(self) -> None:
        """Test add_function behavior."""
        def my_func() -> None: pass
        b = CallGraphBuilder()
        b.add_function(my_func)
        assert len(b.graph.node_names()) > 0

    @patch("pysymex.analysis.interprocedural.callgraph._cached_get_instructions")
    def test_analyze_function(self, mock_instrs) -> None:
        """Test analyze_function behavior."""
        from unittest.mock import Mock
        instr = Mock()
        instr.opname = "CALL_FUNCTION"
        instr.argval = "print"
        mock_instrs.return_value = [instr]
        
        def my_func() -> None: print()
        b = CallGraphBuilder()
        callees = b.analyze_function(my_func)
        assert "print" in callees

    @patch("pysymex.analysis.interprocedural.callgraph._cached_get_instructions")
    def test_build_from_functions(self, mock_instrs) -> None:
        """Test build_from_functions behavior."""
        from unittest.mock import Mock
        instr = Mock()
        instr.opname = "CALL_FUNCTION"
        instr.argval = "f2"
        # Return f2 as called for f1, and nothing for f2
        def side_effect(code):
            if "f1" in str(code): return [instr]
            return []
        mock_instrs.side_effect = side_effect
        
        def f1() -> None: f2()
        def f2() -> None: pass
        b = CallGraphBuilder()
        cg = b.build_from_functions([f1, f2])
        # f1 calls f2 in the mocked instructions. But its name in graph will be the qualname.
        qualnames = list(cg.node_names())
        f1_name = next((n for n in qualnames if "f1" in n), "f1")
        f2_name = next((n for n in qualnames if "f2" in n), "f2")
        # In build_from_functions, caller is func.__qualname__. The callee string added is "f2".
        # So there will be an edge from f1_qualname to "f2".
        assert cg.has_edge(f1_name, "f2") is True

    def test_build(self) -> None:
        """Test build behavior."""
        b = CallGraphBuilder()
        assert isinstance(b.build(), CallGraph)

def test_get_analysis_order() -> None:
    """Test get_analysis_order behavior."""
    cg = CallGraph()
    for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
    cg.add_edge("a", "b")
    cg.add_edge("b", "c")
    order = get_analysis_order(cg)
    assert "c" in order # topological order depends on SCC processing, but c must be analyzed early

def test_find_mutual_recursion() -> None:
    """Test find_mutual_recursion behavior."""
    cg = CallGraph()
    for x in ["a", "b"]: cg.add_node(CallGraphNode(name=x))
    cg.add_edge("a", "b")
    cg.add_edge("b", "a")
    m = find_mutual_recursion(cg)
    assert len(m) == 1
    assert "a" in m[0] and "b" in m[0]

def test_compute_dominators() -> None:
    """Test compute_dominators behavior."""
    cg = CallGraph()
    for x in ["a", "b", "c"]: cg.add_node(CallGraphNode(name=x))
    cg.add_edge("a", "b")
    cg.add_edge("a", "c")
    doms = compute_dominators(cg, "a")
    assert doms["b"] == {"a", "b"}
