import pytest
import z3
from unittest.mock import Mock, patch
from pysymex.analysis.solver.analyzer import FunctionAnalyzer
from pysymex.analysis.solver.graph import SymbolicState
from pysymex.analysis.solver.types import SymValue, SymType, BugType, CrashCondition


def make_dummy_code() -> object:
    def f(a: int) -> int:
        b = a + 1
        return b

    return f.__code__


class TestFunctionAnalyzer:
    """Test suite for pysymex.analysis.solver.analyzer.FunctionAnalyzer."""

    def test_analyze(self) -> None:
        """Test analyze behavior."""
        engine = Mock(max_depth=5)
        analyzer = FunctionAnalyzer(engine)
        code = make_dummy_code()
        crashes, summary = analyzer.analyze(code)
        assert isinstance(crashes, list)
        assert summary.name == "f"
        assert "a" in summary.parameters

    def test_do_binary_op(self) -> None:
        """Test do_binary_op behavior."""
        engine = Mock()
        analyzer = FunctionAnalyzer(engine)
        state = SymbolicState()
        left = SymValue(z3.IntVal(10), "l", SymType.INT)
        right = SymValue(z3.IntVal(2), "r", SymType.INT)
        res = analyzer.do_binary_op(left, right, "+", state)
        assert res.sym_type == SymType.INT

    def test_get_branch_constraint(self) -> None:
        """Test get_branch_constraint behavior."""
        engine = Mock()
        analyzer = FunctionAnalyzer(engine)
        cond = SymValue(z3.Bool("cond"), "c", SymType.BOOL)
        c_fall = analyzer.get_branch_constraint("POP_JUMP_IF_FALSE", "fall", cond)
        assert c_fall is not None
        c_jump = analyzer.get_branch_constraint("POP_JUMP_IF_FALSE", "jump", cond)
        assert c_jump is not None

    def test_op_call(self) -> None:
        """Test op_call behavior."""
        engine = Mock()
        analyzer = FunctionAnalyzer(engine)
        state = SymbolicState()
        state.push(SymValue(z3.Int("f"), "my_func", SymType.CALLABLE))
        state.push(SymValue(z3.IntVal(1), "arg", SymType.INT))
        crashes: list[CrashCondition] = []
        call_sites = []
        analyzer.op_call(1, state, crashes, call_sites)
        assert len(call_sites) == 1
        assert call_sites[0].callee == "my_func"

    def test_op_store_attr(self) -> None:
        """Test op_store_attr behavior."""
        engine = Mock()
        analyzer = FunctionAnalyzer(engine)
        state = SymbolicState()
        state.push(SymValue(z3.IntVal(0), "obj", SymType.NONE, is_none=True))
        state.push(SymValue(z3.IntVal(1), "val", SymType.INT))
        crashes: list[CrashCondition] = []
        analyzer.op_store_attr("attr", state, crashes, [])
        assert len(crashes) == 1
        assert crashes[0].bug_type == BugType.NONE_DEREFERENCE

    def test_op_call_function_ex(self) -> None:
        """Test op_call_function_ex behavior."""
        engine = Mock()
        analyzer = FunctionAnalyzer(engine)
        state = SymbolicState()
        state.push(SymValue(z3.Int("f"), "my_func", SymType.CALLABLE))
        state.push(SymValue(z3.Int("args"), "args", SymType.TUPLE))
        crashes: list[CrashCondition] = []
        call_sites = []
        analyzer.op_call_function_ex(0, state, crashes, call_sites)
        assert len(call_sites) == 1
