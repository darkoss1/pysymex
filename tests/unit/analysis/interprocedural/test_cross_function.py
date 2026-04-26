import pytest
from unittest.mock import Mock, patch
import z3
import types
from pysymex.analysis.interprocedural.cross_function import (
    CallType,
    CallSite,
    FunctionSummary,
    CallGraph,
    InterproceduralAnalyzer,
    CallContext,
    ContextSensitiveAnalyzer,
)
from pysymex.execution.executors import ExecutionResult


def make_dummy_func() -> types.FunctionType:
    def f() -> int:
        return 1

    return f


class TestCallType:
    """Test suite for pysymex.analysis.interprocedural.cross_function.CallType."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert CallType.DIRECT.name == "DIRECT"


class TestCallSite:
    """Test suite for pysymex.analysis.interprocedural.cross_function.CallSite."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        site = CallSite("caller", "callee", CallType.DIRECT, 10)
        assert site.caller == "caller"
        assert site.call_type == CallType.DIRECT


class TestFunctionSummary:
    """Test suite for pysymex.analysis.interprocedural.cross_function.FunctionSummary."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        x = z3.Int("x")
        summary = FunctionSummary("f", ["x"], return_expr=x + 1)

        arg = Mock()
        arg.z3_expr = z3.IntVal(5)
        state = Mock()

        res, constraints = summary.apply([arg], state)
        assert res is not None
        assert z3.simplify(res).eq(z3.IntVal(6))


class TestCallGraph:
    """Test suite for pysymex.analysis.interprocedural.cross_function.CallGraph."""

    def test_add_function(self) -> None:
        """Test add_function behavior."""
        cg = CallGraph()
        cg.add_function("f")
        assert "f" in cg._nodes

    def test_add_call(self) -> None:
        """Test add_call behavior."""
        cg = CallGraph()
        site = CallSite("a", "b", CallType.DIRECT, 10)
        cg.add_call("a", "b", site)
        assert "b" in cg._edges["a"]
        assert len(cg._call_sites[("a", "b")]) == 1

    def test_get_callees(self) -> None:
        """Test get_callees behavior."""
        cg = CallGraph()
        cg.add_call("a", "b", CallSite("a", "b", CallType.DIRECT, 10))
        assert "b" in cg.get_callees("a")

    def test_get_callers(self) -> None:
        """Test get_callers behavior."""
        cg = CallGraph()
        cg.add_call("a", "b", CallSite("a", "b", CallType.DIRECT, 10))
        assert "a" in cg.get_callers("b")

    def test_get_call_sites(self) -> None:
        """Test get_call_sites behavior."""
        cg = CallGraph()
        site = CallSite("a", "b", CallType.DIRECT, 10)
        cg.add_call("a", "b", site)
        assert len(cg.get_call_sites("a", "b")) == 1

    def test_is_recursive(self) -> None:
        """Test is_recursive behavior."""
        cg = CallGraph()
        cg.add_call("a", "a", CallSite("a", "a", CallType.DIRECT, 10))
        assert cg.is_recursive("a") is True
        assert cg.is_recursive("unknown") is False

    def test_topological_order(self) -> None:
        """Test topological_order behavior."""
        cg = CallGraph()
        cg.add_call("a", "b", CallSite("a", "b", CallType.DIRECT, 10))
        cg.add_call("b", "c", CallSite("b", "c", CallType.DIRECT, 10))
        order = cg.topological_order()
        assert order == ["c", "b", "a"]

    def test_add_summary(self) -> None:
        """Test add_summary behavior."""
        cg = CallGraph()
        summary = FunctionSummary("f", [])
        cg.add_summary("f", summary)
        assert cg._summaries["f"] is summary

    def test_get_summary(self) -> None:
        """Test get_summary behavior."""
        cg = CallGraph()
        summary = FunctionSummary("f", [])
        cg.add_summary("f", summary)
        assert cg.get_summary("f") is summary
        assert cg.get_summary("unknown") is None

    def test_to_dot(self) -> None:
        """Test to_dot behavior."""
        cg = CallGraph()
        cg.add_call("a", "b", CallSite("a", "b", CallType.DIRECT, 10))
        dot = cg.to_dot()
        assert '"a" -> "b"' in dot


class TestInterproceduralAnalyzer:
    """Test suite for pysymex.analysis.interprocedural.cross_function.InterproceduralAnalyzer."""

    @patch("pysymex.execution.executors.SymbolicExecutor")
    def test_analyze_module(self, mock_executor) -> None:
        """Test analyze_module behavior."""
        mock_instance = Mock()
        mock_result = Mock(issues=[], paths_explored=1)
        mock_instance.execute_function.return_value = mock_result
        mock_executor.return_value = mock_instance

        analyzer = InterproceduralAnalyzer()
        mod = types.ModuleType("test_mod")
        f = make_dummy_func()
        f.__module__ = "test_mod"
        setattr(mod, "f", f)

        res = analyzer.analyze_module(mod)
        assert "f" in res
        assert isinstance(analyzer.call_graph.get_summary("f"), FunctionSummary)

    def test_should_inline(self) -> None:
        """Test should_inline behavior."""
        analyzer = InterproceduralAnalyzer(max_inline_depth=2, max_recursion_depth=1)
        assert analyzer.should_inline("f", 3) is False
        assert analyzer.should_inline("f", 1) is True

        analyzer.call_graph.add_call("r", "r", CallSite("r", "r", CallType.DIRECT, 10))
        assert analyzer.should_inline("r", 2) is False

    def test_get_call_graph_dot(self) -> None:
        """Test get_call_graph_dot behavior."""
        analyzer = InterproceduralAnalyzer()
        analyzer.call_graph.add_call("a", "b", CallSite("a", "b", CallType.DIRECT, 10))
        dot = analyzer.get_call_graph_dot()
        assert "digraph CallGraph" in dot


class TestCallContext:
    """Test suite for pysymex.analysis.interprocedural.cross_function.CallContext."""

    def test_extend(self) -> None:
        """Test extend behavior."""
        ctx = CallContext(call_string=("a",), max_length=2)
        ctx2 = ctx.extend("b")
        assert ctx2.call_string == ("a", "b")
        ctx3 = ctx2.extend("c")
        assert ctx3.call_string == ("b", "c")


class TestContextSensitiveAnalyzer:
    """Test suite for pysymex.analysis.interprocedural.cross_function.ContextSensitiveAnalyzer."""

    @patch("pysymex.execution.executors.SymbolicExecutor")
    def test_analyze_with_context(self, mock_executor) -> None:
        """Test analyze_with_context behavior."""
        mock_instance = Mock()
        mock_instance.execute_function.return_value = "result"
        mock_executor.return_value = mock_instance

        analyzer = ContextSensitiveAnalyzer()
        ctx = CallContext(call_string=("caller",))
        f = make_dummy_func()
        res = analyzer.analyze_with_context(f, ctx)
        assert res == "result"

        res2 = analyzer.analyze_with_context(f, ctx)
        assert res2 == "result"
        assert mock_instance.execute_function.call_count == 1
