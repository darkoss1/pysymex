import pytest
import dis
import z3
from pysymex.analysis.solver.graph import CallGraph, CFGBuilder, SymbolicState
from pysymex.analysis.solver.types import CallSite, SymValue, SymType

def make_dummy_code() -> object:
    def f() -> None:
        pass
    return f.__code__

class TestCallGraph:
    """Test suite for pysymex.analysis.solver.graph.CallGraph."""
    def test_add_call(self) -> None:
        """Test add_call behavior."""
        cg = CallGraph()
        site = CallSite("f1", "f2", 10, [])
        cg.add_call(site)
        assert "f2" in cg.calls["f1"]
        assert "f1" in cg.callers["f2"]

    def test_get_callees(self) -> None:
        """Test get_callees behavior."""
        cg = CallGraph()
        cg.add_call(CallSite("f1", "f2", 10, []))
        assert "f2" in cg.get_callees("f1")

    def test_get_callers(self) -> None:
        """Test get_callers behavior."""
        cg = CallGraph()
        cg.add_call(CallSite("f1", "f2", 10, []))
        assert "f1" in cg.get_callers("f2")

    def test_find_recursive(self) -> None:
        """Test find_recursive behavior."""
        cg = CallGraph()
        cg.add_call(CallSite("f1", "f2", 10, []))
        cg.add_call(CallSite("f2", "f1", 10, []))
        rec = cg.find_recursive()
        assert "f1" in rec and "f2" in rec

    def test_topological_order(self) -> None:
        """Test topological_order behavior."""
        cg = CallGraph()
        cg.add_call(CallSite("f1", "f2", 10, []))
        cg.add_call(CallSite("f2", "f3", 10, []))
        order = cg.topological_order()
        assert order == ["f1", "f2", "f3"]

    def test_get_all_affected(self) -> None:
        """Test get_all_affected behavior."""
        cg = CallGraph()
        cg.add_call(CallSite("f1", "f2", 10, []))
        cg.add_call(CallSite("f2", "f3", 10, []))
        affected = cg.get_all_affected("f3")
        assert "f1" in affected and "f2" in affected

class TestCFGBuilder:
    """Test suite for pysymex.analysis.solver.graph.CFGBuilder."""
    def test_build(self) -> None:
        """Test build behavior."""
        builder = CFGBuilder()
        code = make_dummy_code() # type: ignore[arg-type]
        cfg = builder.build(code)
        assert len(cfg) > 0
        assert 0 in cfg

class TestSymbolicState:
    """Test suite for pysymex.analysis.solver.graph.SymbolicState."""
    def test_fork(self) -> None:
        """Test fork behavior."""
        state = SymbolicState()
        state.set_var("x", SymValue(z3.IntVal(1), "x", SymType.INT))
        state.add_constraint(z3.BoolVal(True))
        forked = state.fork()
        assert forked.parent is state
        assert "x" in forked.variables
        assert len(forked.path_constraints) == 1

    def test_fresh_name(self) -> None:
        """Test fresh_name behavior."""
        state = SymbolicState()
        n1 = state.fresh_name("var")
        n2 = state.fresh_name("var")
        assert n1 != n2

    def test_add_constraint(self) -> None:
        """Test add_constraint behavior."""
        state = SymbolicState()
        state.add_constraint(z3.BoolVal(True))
        assert len(state.path_constraints) == 1

    def test_get_var(self) -> None:
        """Test get_var behavior."""
        state = SymbolicState()
        val = SymValue(z3.IntVal(1), "x", SymType.INT)
        state.set_var("x", val)
        assert state.get_var("x") is val
        assert state.get_var("y") is None

    def test_set_var(self) -> None:
        """Test set_var behavior."""
        state = SymbolicState()
        val = SymValue(z3.IntVal(1), "x", SymType.INT)
        state.set_var("x", val)
        assert "x" in state.variables

    def test_push(self) -> None:
        """Test push behavior."""
        state = SymbolicState()
        val = SymValue(z3.IntVal(1), "x", SymType.INT)
        state.push(val)
        assert len(state.stack) == 1

    def test_pop(self) -> None:
        """Test pop behavior."""
        state = SymbolicState()
        val = SymValue(z3.IntVal(1), "x", SymType.INT)
        state.push(val)
        assert state.pop() is val
        assert state.pop() is None

    def test_peek(self) -> None:
        """Test peek behavior."""
        state = SymbolicState()
        val = SymValue(z3.IntVal(1), "x", SymType.INT)
        state.push(val)
        assert state.peek() is val
        assert state.peek(2) is None
