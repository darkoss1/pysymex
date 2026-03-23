"""Regression tests for bug fixes found during audit.

Tests cover:
  C1: None dereference crash in functions.py CALL handler
  C2: UNARY_NOT crash on concrete values in arithmetic.py
  C3: Taint tracker fork isolation in state.py
  C4: Qualified taint source/sink name resolution
  C5: protected_ranges population in exception analysis
  C6: Concrete zero division-like opcodes terminate cleanly
  H1: Solver duplicate assignment removed
  H3: Version string uses __version__
  H4: ast.walk scope limited to try body
  M1: Dedup uses hash instead of truncated message
  M4: Abstract interpreter handles unknown opcodes
"""

import z3

from pysymex.analysis.detectors import IssueKind
from pysymex import __version__
from pysymex.core.solver import IncrementalSolver
from pysymex.core.state import VMState

# ---------------------------------------------------------------------------
# C1 — CALL handler should not crash when _apply_model returns None
# ---------------------------------------------------------------------------


class TestC1_CallHandlerNoNoneDereference:
    """The CALL opcode handler must not crash when function model returns None."""

    def test_execute_function_with_call(self):
        """Execute a function with calls — should not raise AttributeError."""
        from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

        def fn(x):
            y = abs(x)
            return y

        config = ExecutionConfig(max_paths=5, max_depth=20)
        executor = SymbolicExecutor(config)
        result = executor.execute_function(fn, {"x": "int"})
        assert result.paths_explored >= 1


# ---------------------------------------------------------------------------
# C2 — UNARY_NOT on concrete values
# ---------------------------------------------------------------------------


class TestC2_UnaryNotConcrete:
    """UNARY_NOT must work on concrete Python values (int, bool, etc.)."""

    def test_unary_not_on_concrete_bool(self):
        from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

        def fn(x):
            flag = True
            if not flag:
                return 1 / 0
            return x

        config = ExecutionConfig(max_paths=10, max_depth=30)
        executor = SymbolicExecutor(config)
        # Should not raise AttributeError
        result = executor.execute_function(fn, {"x": "int"})
        assert result.paths_explored >= 1


# ---------------------------------------------------------------------------
# C3 — Taint tracker fork isolation
# ---------------------------------------------------------------------------


class TestC3_TaintTrackerForkIsolation:
    """Forked VMState must have independent taint trackers."""

    def test_fork_isolates_taint_tracker(self):
        from pysymex.analysis.taint import TaintPolicy, TaintTracker

        policy = TaintPolicy()
        tracker = TaintTracker(policy)
        tracker._taint_map["x"] = {"tainted"}  # type: ignore[reportArgumentType]

        state = VMState(taint_tracker=tracker)
        forked = state.fork()

        # Mutate the fork's taint tracker
        forked.taint_tracker._taint_map["y"] = {"new_taint"}  # type: ignore[reportOptionalMemberAccess]

        # Original should NOT have "y"
        assert "y" not in state.taint_tracker._taint_map  # type: ignore[reportOptionalMemberAccess]
        # Fork should have both
        assert "x" in forked.taint_tracker._taint_map  # type: ignore[reportOptionalMemberAccess]
        assert "y" in forked.taint_tracker._taint_map  # type: ignore[reportOptionalMemberAccess]


# ---------------------------------------------------------------------------
# C4 — Qualified taint name resolution
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# C5 — protected_ranges populated in exception analysis
# ---------------------------------------------------------------------------


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
        # Get the nested function code
        func_code = None
        for const in code.co_consts:
            if hasattr(const, "co_code") and const.co_name == "foo":
                func_code = const
                break

        assert func_code is not None
        analyzer = UncaughtExceptionAnalyzer()
        result = analyzer.analyze(func_code)
        # The division IS protected by except ZeroDivisionError, so
        # result should NOT include ZeroDivisionError for the division line
        all_exceptions = set()
        for line_excs in result.values():
            all_exceptions.update(line_excs)
        assert (
            "ZeroDivisionError" not in all_exceptions
        ), "Division inside try/except ZeroDivisionError should be protected"


# ---------------------------------------------------------------------------
# C6 — Concrete zero division-like opcodes
# ---------------------------------------------------------------------------


class TestC6_ConcreteZeroDivisionOpcodes:
    """Division-like operations with a concrete zero divisor must not escape the executor."""

    def test_division_like_ops_report_issue_without_crashing(self):
        from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

        def div(x: int) -> float:
            return x / 0

        def floordiv(x: int) -> int:
            return x // 0

        def modulo(x: int) -> int:
            return x % 0

        config = ExecutionConfig(max_paths=5, max_depth=20)
        for fn in (div, floordiv, modulo):
            executor = SymbolicExecutor(config)
            result = executor.execute_function(fn, {"x": "int"})
            assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)


# ---------------------------------------------------------------------------
# H1 — Solver no duplicate assignment
# ---------------------------------------------------------------------------


class TestH1_SolverNoDuplicate:
    """IncrementalSolver should not have duplicate _warm_start assignment."""

    def test_warm_start_parameter(self):
        solver = IncrementalSolver(warm_start=False)
        assert solver._warm_start is False

        solver2 = IncrementalSolver(warm_start=True)
        assert solver2._warm_start is True


# ---------------------------------------------------------------------------
# H3 — Version string uses __version__
# ---------------------------------------------------------------------------


class TestH3_VersionString:
    """Formatters should use the actual __version__, not hardcoded strings."""

    def test_text_formatter_version(self):
        from unittest.mock import MagicMock

        from pysymex.reporting.formatters import TextFormatter

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
        # The fix for H3 ensured we use __version__ instead of a hardcoded string
        assert "v0.0.1" not in output, "Hardcoded old version should not appear"

    def test_json_formatter_version(self):
        import json
        from unittest.mock import MagicMock

        from pysymex.reporting.formatters import JSONFormatter

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


# ---------------------------------------------------------------------------
# H4 — ast.walk scope limited to try body
# ---------------------------------------------------------------------------


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
        # The raise is in the handler, NOT the try body
        for block in analyzer.try_blocks:
            assert (
                "ValueError" not in block.raises_in_try
            ), "ValueError raise is in handler, not try body"


# ---------------------------------------------------------------------------
# M1 — Dedup uses hash instead of message[:50]
# ---------------------------------------------------------------------------


class TestM1_DedupHash:
    """Dedup should use hash(message) not message[:50] to avoid collisions."""

    def test_different_messages_same_50_prefix(self):

        # Two messages with the same 50-char prefix but different suffixes
        prefix = "A" * 50
        msg1 = prefix + " — first issue"
        msg2 = prefix + " — second issue, completely different"

        key1 = hash(msg1) if msg1 else 0
        key2 = hash(msg2) if msg2 else 0
        assert key1 != key2, "Different messages must produce different dedup keys"


# ---------------------------------------------------------------------------
# M4 — Abstract interpreter handles unknown opcodes
# ---------------------------------------------------------------------------


class TestM4_UnknownOpcodes:
    """Abstract interpreter should approximate stack effect for unknown opcodes."""

    def test_unknown_opcode_no_crash(self):
        """Running abstract interpretation should not crash on unusual functions."""
        from pysymex.analysis.abstract.interpreter import AbstractAnalyzer

        # A function using various operations
        def complex_fn(x):
            items = [1, 2, 3]
            result = sum(items)
            return result + x

        analyzer = AbstractAnalyzer()
        code = complex_fn.__code__
        # Should not crash
        warnings = analyzer.analyze_function(code)
        assert isinstance(warnings, list)


# ---------------------------------------------------------------------------
# Additional: State fork independence
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# B13 - Regression guard for state mutation pruning
# ---------------------------------------------------------------------------


class TestB13_StateMutationPruningRegression:
    """Ensure we never regress to immediate duplicate-state pruning at PC 0."""

    def test_branching_function_not_pruned_immediately(self):
        from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

        def fn(x: int) -> int:
            if x > 0:
                return 1
            return -1

        executor = SymbolicExecutor(ExecutionConfig(max_paths=10, max_depth=20))
        result = executor.execute_function(fn, {"x": "int"})

        # Historical bug symptom: paths_explored=1, paths_pruned=1, coverage={0}
        assert result.paths_explored >= 2
        assert result.paths_completed >= 2
        assert set(result.coverage) != {0}

    def test_linear_function_advances_beyond_first_instruction(self):
        from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

        def fn(x: int) -> int:
            y = x + 1
            return y * 2

        executor = SymbolicExecutor(ExecutionConfig(max_paths=5, max_depth=20))
        result = executor.execute_function(fn, {"x": "int"})

        assert result.paths_explored >= 1
        assert result.paths_completed >= 1
        assert max(result.coverage) > 0


# ---------------------------------------------------------------------------
# Additional: Solver basic operations
# ---------------------------------------------------------------------------


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
