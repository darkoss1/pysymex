"""Tests for pysymex.analysis.concolic -- Concolic execution engine.

Covers:
- ConcreteInput creation and hashing
- BranchRecord creation and negation
- ExecutionTrace path condition and hashing
- ConcolicExecutor instantiation and reset
- ConcolicResult properties
- GenerationalSearch instantiation
- ConcolicExecutor.execute on simple functions
"""

from __future__ import annotations

import pytest
import z3

from pysymex.analysis.concolic import (
    BranchRecord,
    ConcolicExecutor,
    ConcolicResult,
    ConcreteInput,
    ExecutionTrace,
    GenerationalSearch,
)


# ---------------------------------------------------------------------------
# ConcreteInput tests
# ---------------------------------------------------------------------------


class TestConcreteInput:
    """Tests for ConcreteInput dataclass."""

    def test_creation(self):
        ci = ConcreteInput(values={"x": 1, "y": 2})
        assert ci.values == {"x": 1, "y": 2}
        assert ci.generation == 0
        assert ci.parent is None
        assert ci.branch_flipped is None

    def test_hash_deterministic(self):
        ci = ConcreteInput(values={"x": 1})
        assert hash(ci) == hash(ci)

    def test_equal_same_values(self):
        a = ConcreteInput(values={"x": 1})
        b = ConcreteInput(values={"x": 1})
        assert a == b

    def test_not_equal_different_values(self):
        a = ConcreteInput(values={"x": 1})
        b = ConcreteInput(values={"x": 2})
        assert a != b

    def test_not_equal_to_non_input(self):
        ci = ConcreteInput(values={"x": 1})
        assert ci != "not an input"

    def test_generation_tracking(self):
        parent = ConcreteInput(values={"x": 1}, generation=0)
        child = ConcreteInput(
            values={"x": 2}, generation=1, parent=parent, branch_flipped=0
        )
        assert child.generation == 1
        assert child.parent is parent
        assert child.branch_flipped == 0

    def test_empty_values(self):
        ci = ConcreteInput(values={})
        assert ci.values == {}


# ---------------------------------------------------------------------------
# BranchRecord tests
# ---------------------------------------------------------------------------


class TestBranchRecord:
    """Tests for BranchRecord."""

    def test_creation(self):
        cond = z3.Bool("c")
        br = BranchRecord(pc=10, condition=cond, taken=True)
        assert br.pc == 10
        assert br.taken is True

    def test_negate_when_taken(self):
        cond = z3.Bool("c")
        br = BranchRecord(pc=10, condition=cond, taken=True)
        neg = br.negate()
        # Should be Not(cond)
        s = z3.Solver()
        s.add(neg)
        s.add(cond)
        assert s.check() == z3.unsat

    def test_negate_when_not_taken(self):
        cond = z3.Bool("c")
        br = BranchRecord(pc=10, condition=cond, taken=False)
        neg = br.negate()
        # Should be cond itself
        s = z3.Solver()
        s.add(neg)
        s.add(z3.Not(cond))
        assert s.check() == z3.unsat

    def test_line_number_optional(self):
        cond = z3.Bool("c")
        br = BranchRecord(pc=10, condition=cond, taken=True, line_number=42)
        assert br.line_number == 42


# ---------------------------------------------------------------------------
# ExecutionTrace tests
# ---------------------------------------------------------------------------


class TestExecutionTrace:
    """Tests for ExecutionTrace."""

    def test_empty_trace(self):
        ci = ConcreteInput(values={"x": 1})
        trace = ExecutionTrace(input=ci)
        assert trace.branches == []
        assert trace.coverage == set()
        assert trace.result is None
        assert trace.exception is None

    def test_path_condition_empty(self):
        ci = ConcreteInput(values={"x": 1})
        trace = ExecutionTrace(input=ci)
        assert trace.path_condition() == []

    def test_path_condition_with_branches(self):
        ci = ConcreteInput(values={"x": 1})
        c1 = z3.Bool("c1")
        c2 = z3.Bool("c2")
        trace = ExecutionTrace(
            input=ci,
            branches=[
                BranchRecord(pc=0, condition=c1, taken=True),
                BranchRecord(pc=10, condition=c2, taken=False),
            ],
        )
        pc = trace.path_condition()
        assert len(pc) == 2

    def test_path_hash_deterministic(self):
        ci = ConcreteInput(values={"x": 1})
        c1 = z3.Bool("c1")
        trace = ExecutionTrace(
            input=ci,
            branches=[BranchRecord(pc=0, condition=c1, taken=True)],
        )
        assert trace.path_hash() == trace.path_hash()

    def test_path_hash_differs_for_different_paths(self):
        ci = ConcreteInput(values={"x": 1})
        c1 = z3.Bool("c1")
        t1 = ExecutionTrace(
            input=ci,
            branches=[BranchRecord(pc=0, condition=c1, taken=True)],
        )
        t2 = ExecutionTrace(
            input=ci,
            branches=[BranchRecord(pc=0, condition=c1, taken=False)],
        )
        assert t1.path_hash() != t2.path_hash()

    def test_coverage_set(self):
        ci = ConcreteInput(values={"x": 1})
        trace = ExecutionTrace(input=ci, coverage={0, 2, 4, 6})
        assert 4 in trace.coverage


# ---------------------------------------------------------------------------
# ConcolicResult tests
# ---------------------------------------------------------------------------


class TestConcolicResult:
    """Tests for ConcolicResult."""

    def test_num_paths_empty(self):
        result = ConcolicResult(traces=[], coverage=set(), iterations=0, time_seconds=0.0)
        assert result.num_paths == 0

    def test_num_paths_with_traces(self):
        ci = ConcreteInput(values={"x": 1})
        traces = [ExecutionTrace(input=ci), ExecutionTrace(input=ci)]
        result = ConcolicResult(traces=traces, coverage={0, 2}, iterations=2, time_seconds=0.1)
        assert result.num_paths == 2

    def test_coverage_percentage(self):
        result = ConcolicResult(traces=[], coverage={0, 2, 4}, iterations=0, time_seconds=0.0)
        assert result.coverage_percentage == 3

    def test_get_failing_inputs_empty(self):
        result = ConcolicResult(traces=[], coverage=set(), iterations=0, time_seconds=0.0)
        assert result.get_failing_inputs() == []

    def test_get_failing_inputs_with_exception(self):
        ci = ConcreteInput(values={"x": 0})
        trace = ExecutionTrace(input=ci, exception=ZeroDivisionError("div by zero"))
        result = ConcolicResult(traces=[trace], coverage=set(), iterations=1, time_seconds=0.1)
        failing = result.get_failing_inputs()
        assert len(failing) == 1
        assert failing[0] == ci

    def test_format_summary(self):
        result = ConcolicResult(traces=[], coverage=set(), iterations=0, time_seconds=0.0)
        summary = result.format_summary()
        assert "Concolic Execution Summary" in summary
        assert "Iterations: 0" in summary


# ---------------------------------------------------------------------------
# ConcolicExecutor instantiation
# ---------------------------------------------------------------------------


class TestConcolicExecutorInit:
    """Tests for ConcolicExecutor initialization."""

    def test_default_params(self):
        executor = ConcolicExecutor()
        assert executor.max_iterations == 100
        assert executor.strategy == "adaptive"

    def test_custom_params(self):
        executor = ConcolicExecutor(max_iterations=10, strategy="random", max_time_seconds=5.0)
        assert executor.max_iterations == 10
        assert executor.strategy == "random"
        assert executor.max_time_seconds == 5.0

    def test_strategies(self):
        for strat in ("chtd_native", "random"):
            executor = ConcolicExecutor(strategy=strat)
            assert executor.strategy == strat


# ---------------------------------------------------------------------------
# ConcolicExecutor.execute on simple functions
# ---------------------------------------------------------------------------


def _identity(x):
    return x


def _simple_branch(x):
    if x > 0:
        return 1
    return 0


def _division(x):
    if x != 0:
        return 10 // x
    return 0


class TestConcolicExecutorExecute:
    """Tests for ConcolicExecutor.execute()."""

    def test_execute_identity(self):
        executor = ConcolicExecutor(max_iterations=3, max_time_seconds=10.0)
        result = executor.execute(
            _identity,
            initial_inputs={"x": 42},
            symbolic_types={"x": "int"},
        )
        assert isinstance(result, ConcolicResult)
        assert result.iterations >= 1

    def test_execute_simple_branch(self):
        executor = ConcolicExecutor(max_iterations=5, max_time_seconds=10.0)
        result = executor.execute(
            _simple_branch,
            initial_inputs={"x": 5},
            symbolic_types={"x": "int"},
        )
        assert isinstance(result, ConcolicResult)
        assert result.iterations >= 1

    def test_execute_division(self):
        executor = ConcolicExecutor(max_iterations=5, max_time_seconds=10.0)
        result = executor.execute(
            _division,
            initial_inputs={"x": 2},
            symbolic_types={"x": "int"},
        )
        assert isinstance(result, ConcolicResult)

    def test_execute_no_initial_inputs(self):
        executor = ConcolicExecutor(max_iterations=3, max_time_seconds=10.0)
        result = executor.execute(
            _identity,
            symbolic_types={"x": "int"},
        )
        assert isinstance(result, ConcolicResult)

    def test_execute_string_type(self):
        def _str_func(s):
            return len(s)

        executor = ConcolicExecutor(max_iterations=2, max_time_seconds=10.0)
        result = executor.execute(
            _str_func,
            initial_inputs={"s": "hello"},
            symbolic_types={"s": "str"},
        )
        assert isinstance(result, ConcolicResult)


# ---------------------------------------------------------------------------
# GenerationalSearch tests
# ---------------------------------------------------------------------------


class TestGenerationalSearch:
    """Tests for GenerationalSearch."""

    def test_instantiation(self):
        gs = GenerationalSearch(max_generations=5)
        assert gs.max_generations == 5

    def test_default_max_generations(self):
        gs = GenerationalSearch()
        assert gs.max_generations == 10


# ---------------------------------------------------------------------------
# ConcolicExecutor internal methods
# ---------------------------------------------------------------------------


class TestConcolicExecutorInternals:
    """Tests for internal helper methods."""

    def test_z3_to_python_int(self):
        executor = ConcolicExecutor()
        val = z3.IntVal(42)
        result = executor._z3_to_python(val)
        assert result == 42

    def test_z3_to_python_bool_true(self):
        executor = ConcolicExecutor()
        val = z3.BoolVal(True)
        result = executor._z3_to_python(val)
        assert result is True

    def test_z3_to_python_bool_false(self):
        executor = ConcolicExecutor()
        val = z3.BoolVal(False)
        result = executor._z3_to_python(val)
        assert result is False

    def test_z3_to_python_string(self):
        executor = ConcolicExecutor()
        val = z3.StringVal("hello")
        result = executor._z3_to_python(val)
        assert result == "hello"
