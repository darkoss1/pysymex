import pytest
import z3
import ast
from pysymex.analysis.cross_function.core import (
    FunctionSummaryCache, CallGraph, CallGraphBuilder, EffectAnalyzer,
    ContextSensitiveAnalyzer, CrossFunctionAnalyzer
)
from pysymex.analysis.cross_function.types import CallContext
from pysymex.core.types.scalars import SymbolicValue

def make_dummy_code() -> object:
    def my_func() -> None:
        print("hello")
    return my_func.__code__

class TestFunctionSummaryCache:
    """Test suite for pysymex.analysis.cross_function.core.FunctionSummaryCache."""
    def test_get(self) -> None:
        """Test get behavior."""
        cache = FunctionSummaryCache()
        assert cache.get("f", [], []) is None
        assert cache._misses == 1

    def test_put(self) -> None:
        """Test put behavior."""
        cache = FunctionSummaryCache()
        sym = z3.Int("x")
        cache.put("f", [1], [sym > 0], "summary1")
        res = cache.get("f", [1], [sym > 0])
        assert res == "summary1"
        assert cache._hits == 1

class TestCallGraph:
    """Test suite for pysymex.analysis.cross_function.core.CallGraph."""
    def test_add_function(self) -> None:
        """Test add_function behavior."""
        cg = CallGraph()
        node = cg.add_function("f1", "mod.f1")
        assert node.name == "f1"
        assert "f1" in cg.nodes

    def test_add_call(self) -> None:
        """Test add_call behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 10, 20)
        assert len(cg.nodes["f1"].callees) == 1
        assert cg.nodes["f1"].callees[0].callee == "f2"
        assert "f1" in cg.nodes["f2"].callers

    def test_get_callees(self) -> None:
        """Test get_callees behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 10, 20)
        assert cg.get_callees("f1") == ["f2"]
        assert cg.get_callees("unknown") == []

    def test_get_callers(self) -> None:
        """Test get_callers behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 10, 20)
        assert "f1" in cg.get_callers("f2")
        assert len(cg.get_callers("unknown")) == 0

    def test_find_recursive(self) -> None:
        """Test find_recursive behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 1, 1)
        cg.add_call("f2", "f1", 2, 2)
        rec = cg.find_recursive()
        assert "f1" in rec and "f2" in rec

    def test_topological_order(self) -> None:
        """Test topological_order behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 1, 1)
        cg.add_call("f2", "f3", 2, 2)
        order = cg.topological_order()
        # Topo order returns callees before callers? Actually the code reverses at the end.
        # queue is nodes with in_degree 0 (nobody calls them). So f1.
        # It processes f1 -> f2 -> f3. Then reverses.
        # Wait, get_callees increments in_degree for callee.
        # So f1 in_deg=0, f2=1, f3=1.
        # Processing: f1 out, decreases f2 to 0. f2 out, decreases f3 to 0. f3 out.
        # Result = [f1, f2, f3]. Reverse -> [f3, f2, f1]
        assert order == ["f3", "f2", "f1"]

    def test_get_reachable(self) -> None:
        """Test get_reachable behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 1, 1)
        cg.add_call("f2", "f3", 2, 2)
        r = cg.get_reachable("f1")
        assert "f1" in r and "f2" in r and "f3" in r

class TestCallGraphBuilder:
    """Test suite for pysymex.analysis.cross_function.core.CallGraphBuilder."""
    def test_build_from_module(self) -> None:
        """Test build_from_module behavior."""
        cgb = CallGraphBuilder()
        code = make_dummy_code() # type: ignore[arg-type]
        cg = cgb.build_from_module(code)
        assert isinstance(cg, CallGraph)
        assert "<module>" in cg.nodes

class TestEffectAnalyzer:
    """Test suite for pysymex.analysis.cross_function.core.EffectAnalyzer."""
    def test_analyze_function(self) -> None:
        """Test analyze_function behavior."""
        ea = EffectAnalyzer()
        code = make_dummy_code() # type: ignore[arg-type]
        summary = ea.analyze_function(code, "my_func")
        assert summary.effects.value >= 0 # Has some effect, probably READ_GLOBAL for print

    def test_analyze_with_call_graph(self) -> None:
        """Test analyze_with_call_graph behavior."""
        ea = EffectAnalyzer()
        cg = CallGraph()
        code = make_dummy_code() # type: ignore[arg-type]
        cg.add_call("f1", "f2", 1, 1)
        summaries = ea.analyze_with_call_graph(cg, {"f1": code, "f2": code})
        assert "f1" in summaries

class TestContextSensitiveAnalyzer:
    """Test suite for pysymex.analysis.cross_function.core.ContextSensitiveAnalyzer."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        csa = ContextSensitiveAnalyzer()
        cg = CallGraph()
        cg.add_function("entry_func")
        cg.entry_points.add("entry_func")
        code = make_dummy_code() # type: ignore[arg-type]
        summaries = csa.analyze(cg, {"entry_func": code})
        key = ("entry_func", CallContext())
        assert key in summaries
        assert summaries[key].function == "entry_func"

class TestCrossFunctionAnalyzer:
    """Test suite for pysymex.analysis.cross_function.core.CrossFunctionAnalyzer."""
    def test_analyze_module(self) -> None:
        """Test analyze_module behavior."""
        cfa = CrossFunctionAnalyzer()
        code = make_dummy_code() # type: ignore[arg-type]
        res = cfa.analyze_module(code)
        assert "call_graph" in res
        assert "effects" in res
        assert "escape" in res
        assert "context_sensitive" in res
