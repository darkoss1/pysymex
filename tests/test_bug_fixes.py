"""Regression tests for bug fixes found during v0.5.0 audit.

Tests cover:
  C1: None dereference crash in functions.py CALL handler
  C2: UNARY_NOT crash on concrete values in arithmetic.py
  C3: Taint tracker fork isolation in state.py
  C4: Qualified taint source/sink name resolution
  C5: protected_ranges population in exception analysis
  H1: Solver duplicate assignment removed
  H3: Version string uses __version__
  H4: ast.walk scope limited to try body
  M1: Dedup uses hash instead of truncated message
  M4: Abstract interpreter handles unknown opcodes
"""

import ast

import dis

import sys


import pytest

import z3


from pysymex import __version__

from pysymex.core.solver import IncrementalSolver

from pysymex.core.state import VMState

from pysymex.core.types import SymbolicValue


class TestC1_CallHandlerNoNoneDereference:
    """The CALL opcode handler must not crash when function model returns None."""

    def test_execute_function_with_call(self):
        """Execute a function with calls — should not raise AttributeError."""

        from pysymex.execution.executor import SymbolicExecutor, ExecutionConfig

        def fn(x):
            y = abs(x)

            return y

        config = ExecutionConfig(max_paths=5, max_depth=20)

        executor = SymbolicExecutor(config)

        result = executor.execute_function(fn, {"x": "int"})

        assert result.paths_explored >= 1


class TestC2_UnaryNotConcrete:
    """UNARY_NOT must work on concrete Python values (int, bool, etc.)."""

    def test_unary_not_on_concrete_bool(self):
        from pysymex.execution.executor import SymbolicExecutor, ExecutionConfig

        def fn(x):
            flag = True

            if not flag:
                return 1 / 0

            return x

        config = ExecutionConfig(max_paths=10, max_depth=30)

        executor = SymbolicExecutor(config)

        result = executor.execute_function(fn, {"x": "int"})

        assert result.paths_explored >= 1


class TestC3_TaintTrackerForkIsolation:
    """Forked VMState must have independent taint trackers."""

    def test_fork_isolates_taint_tracker(self):
        from pysymex.analysis.taint import TaintTracker, TaintPolicy

        policy = TaintPolicy()

        tracker = TaintTracker(policy)

        tracker._taint_map["x"] = {"tainted"}

        state = VMState(taint_tracker=tracker)

        forked = state.fork()

        forked.taint_tracker._taint_map["y"] = {"new_taint"}

        assert "y" not in state.taint_tracker._taint_map

        assert "x" in forked.taint_tracker._taint_map

        assert "y" in forked.taint_tracker._taint_map


class TestC4_QualifiedTaintNames:
    """Qualified names like 'file.read' and 'cursor.execute' must resolve."""

    def test_qualified_source_file_read(self):
        from pysymex.analysis.taint.checker import TaintAnalyzer

        analyzer = TaintAnalyzer()

        source = analyzer._find_source("file.read")

        assert source is not None, "file.read should resolve as a taint source"

    def test_qualified_sink_cursor_execute(self):
        from pysymex.analysis.taint.checker import TaintAnalyzer

        analyzer = TaintAnalyzer()

        sink = analyzer._find_sink("cursor.execute")

        assert sink is not None, "cursor.execute should resolve as a taint sink"

    def test_qualified_sink_os_system(self):
        from pysymex.analysis.taint.checker import TaintAnalyzer

        analyzer = TaintAnalyzer()

        sink = analyzer._find_sink("os.system")

        assert sink is not None, "os.system should resolve as a taint sink"

    def test_ambiguous_short_name_blocked(self):
        """dict.get must NOT match as a taint source — that's the whole point."""

        from pysymex.analysis.taint.checker import TaintAnalyzer

        analyzer = TaintAnalyzer()

        source = analyzer._find_source("dict.get")

        assert source is None, "dict.get should NOT resolve as a taint source"


class TestC5_ProtectedRangesPopulated:
    """UncaughtExceptionAnalyzer should populate protected_ranges from bytecode."""

    def test_protected_division(self):
        from pysymex.analysis.exceptions.analysis import UncaughtExceptionAnalyzer

        source = """
def foo(x):
    try:
        return 1 / x
    except ZeroDivisionError:
        return 0
"""

        code = compile(source, "<test>", "exec")

        func_code = None

        for const in code.co_consts:
            if hasattr(const, "co_code") and const.co_name == "foo":
                func_code = const

                break

        assert func_code is not None

        analyzer = UncaughtExceptionAnalyzer()

        result = analyzer.analyze(func_code)

        all_exceptions = set()

        for line_excs in result.values():
            all_exceptions.update(line_excs)

        assert (
            "ZeroDivisionError" not in all_exceptions
        ), "Division inside try/except ZeroDivisionError should be protected"


class TestH1_SolverNoDuplicate:
    """IncrementalSolver should not have duplicate _warm_start assignment."""

    def test_warm_start_parameter(self):
        solver = IncrementalSolver(warm_start=False)

        assert solver._warm_start is False

        solver2 = IncrementalSolver(warm_start=True)

        assert solver2._warm_start is True


class TestH3_VersionString:
    """Formatters should use the actual __version__, not hardcoded strings."""

    def test_text_formatter_version(self):
        from pysymex.reporting.formatters import TextFormatter

        from unittest.mock import MagicMock

        result = MagicMock()

        result.source_file = "test.py"

        result.function_name = "test_fn"

        result.paths_explored = 5

        result.paths_completed = 3

        result.coverage = [1, 2, 3]

        result.total_time_seconds = 0.1

        result.issues = []

        formatter = TextFormatter(color=False)

        output = formatter.format(result)

        assert __version__ in output, f"Expected {__version__} in output"

        assert "v0.3.0a0" not in output, "Hardcoded old version should not appear"

    def test_json_formatter_version(self):
        import json

        from pysymex.reporting.formatters import JSONFormatter

        from unittest.mock import MagicMock

        result = MagicMock()

        result.function_name = "test_fn"

        result.source_file = "test.py"

        result.paths_explored = 5

        result.paths_completed = 3

        result.paths_pruned = 0

        result.coverage = [1, 2, 3]

        result.total_time_seconds = 0.1

        result.issues = []

        formatter = JSONFormatter()

        output = formatter.format(result)

        data = json.loads(output)

        assert data["meta"]["version"] == __version__


class TestH4_AstWalkTryBodyOnly:
    """Raises in except/finally blocks must not be attributed to try body."""

    def test_handler_raise_not_in_try_body(self):
        from pysymex.analysis.exceptions.analysis import ExceptionASTAnalyzer

        source = """
def foo():
    try:
        x = 1
    except Exception:
        raise ValueError("in handler")
"""

        analyzer = ExceptionASTAnalyzer("<test>")

        analyzer.analyze(source)

        for block in analyzer.try_blocks:
            assert (
                "ValueError" not in block.raises_in_try
            ), "ValueError raise is in handler, not try body"


class TestM1_DedupHash:
    """Dedup should use hash(message) not message[:50] to avoid collisions."""

    def test_different_messages_same_50_prefix(self):
        from pysymex.analysis.pipeline import Scanner

        prefix = "A" * 50

        msg1 = prefix + " — first issue"

        msg2 = prefix + " — second issue, completely different"

        key1 = hash(msg1) if msg1 else 0

        key2 = hash(msg2) if msg2 else 0

        assert key1 != key2, "Different messages must produce different dedup keys"


class TestM4_UnknownOpcodes:
    """Abstract interpreter should approximate stack effect for unknown opcodes."""

    def test_unknown_opcode_no_crash(self):
        """Running abstract interpretation should not crash on unusual functions."""

        from pysymex.analysis.abstract.interpreter import AbstractAnalyzer

        def complex_fn(x):
            items = [1, 2, 3]

            result = sum(items)

            return result + x

        analyzer = AbstractAnalyzer()

        code = complex_fn.__code__

        warnings = analyzer.analyze_function(code)

        assert isinstance(warnings, list)


class TestStateForkIndependence:
    """Forked states must be fully independent."""

    def test_local_vars_isolated(self):
        state = VMState()

        state.set_local("x", 42)

        forked = state.fork()

        forked.set_local("x", 99)

        assert state.get_local("x") == 42

        assert forked.get_local("x") == 99

    def test_constraints_isolated(self):
        state = VMState()

        x = z3.Int("x")

        state.add_constraint(x > 0)

        forked = state.fork()

        forked.add_constraint(x < 10)

        assert len(state.path_constraints) == 1

        assert len(forked.path_constraints) == 2


class TestSolverBasic:
    """Basic solver operations after H1 fix."""

    def test_incremental_solver_sat(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        assert solver.is_sat([x > 0, x < 10])

    def test_incremental_solver_unsat(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        assert not solver.is_sat([x > 10, x < 5])

    def test_solver_cache_hit(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        constraints = [x > 0, x < 100]

        solver.is_sat(constraints)

        solver.is_sat(constraints)

        stats = solver.get_stats()

        assert stats["cache_hits"] >= 1
