"""Adversarial soundness tests for analysis.solver."""

from __future__ import annotations

from unittest.mock import MagicMock
import dis

from pysymex.analysis.solver import Z3Engine
from pysymex.analysis.solver.analyzer import FunctionAnalyzer
from pysymex.analysis.solver.graph import CFGBuilder, SymbolicState
from pysymex.analysis.solver.types import (
    BugType,
    CrashCondition,
    Severity,
    SymType,
    SymValue,
    TaintInfo,
    TaintSource,
    z3,
)


def _make_analyzer() -> FunctionAnalyzer:
    analyzer = FunctionAnalyzer(engine=MagicMock())
    analyzer.current_function = "test_fn"
    analyzer.current_line = 1
    analyzer.current_file = "<test>"
    return analyzer


def test_call_without_null_sentinel_keeps_function_identity() -> None:
    """CALL must preserve callee identity even when no NULL sentinel is present."""
    analyzer = _make_analyzer()
    state = SymbolicState()
    call_sites = []
    crashes = []

    state.push(SymValue(expr=z3.Int("fn_eval"), name="eval", sym_type=SymType.CALLABLE))
    state.push(SymValue(expr=z3.IntVal(7), name="arg", sym_type=SymType.INT))

    call_handler = getattr(analyzer, "_op_CALL")
    call_handler(1, state, crashes, call_sites)

    assert len(call_sites) == 1
    assert call_sites[0].callee == "eval"


def test_tainted_sink_detection_without_null_sentinel() -> None:
    """Taint-to-sink must trigger for CALL even if stack has no NULL sentinel."""
    analyzer = _make_analyzer()
    state = SymbolicState()
    call_sites = []
    crashes = []

    tainted = SymValue(
        expr=z3.Int("tainted"),
        name="user_input",
        sym_type=SymType.INT,
        taint=TaintInfo(is_tainted=True, sources={TaintSource.USER_INPUT}),
    )
    state.push(SymValue(expr=z3.Int("fn_eval"), name="eval", sym_type=SymType.CALLABLE))
    state.push(tainted)

    call_handler = getattr(analyzer, "_op_CALL")
    call_handler(1, state, crashes, call_sites)

    assert any(c.bug_type == BugType.TAINTED_SINK for c in crashes)


def test_call_function_ex_tainted_sink_detected() -> None:
    analyzer = _make_analyzer()
    state = SymbolicState()
    call_sites = []
    crashes = []

    tainted_starargs = SymValue(
        expr=z3.Int("starargs"),
        name="starargs",
        sym_type=SymType.TUPLE,
        taint=TaintInfo(is_tainted=True, sources={TaintSource.USER_INPUT}),
    )
    state.push(SymValue(expr=z3.Int("fn_eval"), name="eval", sym_type=SymType.CALLABLE))
    state.push(tainted_starargs)

    call_handler = getattr(analyzer, "_op_CALL_FUNCTION_EX")
    call_handler(0, state, crashes, call_sites)

    assert len(call_sites) == 1
    assert call_sites[0].callee == "eval"
    assert any(c.bug_type == BugType.TAINTED_SINK for c in crashes)


def test_cfg_builder_for_iter_has_two_successors() -> None:
    def fn(xs):
        total = 0
        for x in xs:
            total += x
        return total

    cfg = CFGBuilder().build(fn.__code__)
    for_iter_blocks = [b for b in cfg.values() if b.instructions and b.instructions[-1].opname == "FOR_ITER"]
    assert for_iter_blocks
    assert any(len(b.successors) >= 2 for b in for_iter_blocks)


def test_verify_crashes_keeps_distinct_same_line_same_bug() -> None:
    engine = Z3Engine()
    c1 = CrashCondition(
        bug_type=BugType.DIVISION_BY_ZERO,
        condition=z3.BoolVal(True),
        path_constraints=[],
        line=10,
        function="f",
        description="x can be zero",
        variables={"x": z3.Int("x")},
        severity=Severity.CRITICAL,
    )
    c2 = CrashCondition(
        bug_type=BugType.DIVISION_BY_ZERO,
        condition=z3.BoolVal(True),
        path_constraints=[],
        line=10,
        function="f",
        description="y can be zero",
        variables={"y": z3.Int("y")},
        severity=Severity.CRITICAL,
    )

    results = engine._verify_crashes([c1, c2])
    assert len(results) == 2


def test_execute_instruction_dispatches_real_opcode_handler() -> None:
    """_execute_instruction must dispatch to real _op_* handlers, not unknown fallback."""

    def _plus(a, b):
        return a + b

    analyzer = _make_analyzer()
    state = SymbolicState()
    call_sites = []
    crashes = []

    state.push(SymValue(expr=z3.IntVal(1), name="a", sym_type=SymType.INT))
    state.push(SymValue(expr=z3.IntVal(2), name="b", sym_type=SymType.INT))

    instr = next(i for i in dis.get_instructions(_plus) if i.opname == "BINARY_OP")
    analyzer._execute_instruction(instr, state, crashes, call_sites)

    assert len(state.stack) == 1
    assert state.stack[-1].name == "(a+b)"


def test_symbolic_state_fresh_name_has_no_whitespace() -> None:
    state = SymbolicState()
    for _ in range(5):
        name = state.fresh_name("tmp")
        assert " " not in name
        assert name.startswith("tmp_")


def test_store_attr_none_object_reports_none_dereference() -> None:
    analyzer = _make_analyzer()
    state = SymbolicState()
    call_sites = []
    crashes = []

    none_obj = SymValue(expr=z3.IntVal(0), name="obj", sym_type=SymType.NONE, is_none=True)
    value = SymValue(expr=z3.IntVal(7), name="value", sym_type=SymType.INT)
    state.push(none_obj)
    state.push(value)

    store_attr = getattr(analyzer, "_op_STORE_ATTR")
    store_attr("field", state, crashes, call_sites)

    assert any(c.bug_type == BugType.NONE_DEREFERENCE for c in crashes)
