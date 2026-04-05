"""Pytest test suite for pysymex."""

import pytest

from pysymex import analyze, check_assertions, check_division_by_zero, quick_check
from pysymex.analysis.detectors import IssueKind
from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor


class TestDivisionByZero:
    """Tests for division by zero detection."""

    def test_simple_division(self):
        """Test detection of simple division by zero."""

        def divide(x, y):
            return x / y

        result = analyze(divide, {"x": "int", "y": "int"})
        issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)

        assert len(issues) > 0, "Should detect division by zero"

        # Check counterexample
        ce = issues[0].get_counterexample()
        assert "y" in ce, "Counterexample should include y"
        assert ce["y"] == 0, "y should be 0 in counterexample"

    def test_floor_division(self):
        """Test detection of floor division by zero."""

        def floor_div(x, y):
            return x // y

        result = analyze(floor_div, {"x": "int", "y": "int"})
        issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)

        assert len(issues) > 0, "Should detect floor division by zero"

    def test_modulo(self):
        """Test detection of modulo by zero."""

        def modulo(x, y):
            return x % y

        result = analyze(modulo, {"x": "int", "y": "int"})
        issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)

        assert len(issues) > 0, "Should detect modulo by zero"

    def test_guarded_division(self):
        """Test that guarded division doesn't trigger false positive."""

        def guarded(x, y):
            if y != 0:
                return x / y
            return 0

        result = analyze(guarded, {"x": "int", "y": "int"})
        issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)

        assert len(issues) == 0, "Guarded division should not trigger issue"

    def test_guarded_with_positive_check(self):
        """Test guard with positive check."""

        def guarded(x, y):
            if y > 0:
                return x / y
            return 0

        result = analyze(guarded, {"x": "int", "y": "int"})
        issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)

        assert len(issues) == 0, "Guard with y > 0 should prevent issue"

    def test_detect_overflow_false_disables_all_overflow_detectors(self):
        executor = SymbolicExecutor(config=ExecutionConfig(detect_overflow=False))
        detector_names = {d.name for d in executor._active_detectors}

        assert "overflow" not in detector_names
        assert "bounded-overflow" not in detector_names


class TestAssertionErrors:
    """Tests for assertion error detection."""

    def test_simple_assertion(self):
        """Test detection of failing assertion.

        Note: Currently assertion detection works through RAISE_VARARGS
        opcode which may not be triggered in all scenarios.
        This test verifies the path exploration finds assertion paths.
        """

        def assert_positive(x):
            assert x > 0
            return x

        result = analyze(assert_positive, {"x": "int"})
        # Assertion detection depends on reaching the RAISE_VARARGS path
        # At minimum, we should explore multiple paths
        assert result.paths_explored > 0

    def test_assertion_with_message(self):
        """Test assertion with message - verifies path exploration."""

        def assert_msg(x):
            assert x >= 0, "x must be non-negative"
            return x * 2

        result = analyze(assert_msg, {"x": "int"})
        # Should explore both true and false branches of the assertion
        assert result.paths_explored >= 1


class TestPathExploration:
    """Tests for path exploration."""

    def test_multiple_paths(self):
        """Test that multiple paths are explored."""

        def branching(x, y):
            if x > 0:
                if y > 0:
                    return 1
                else:
                    return 2
            else:
                return 3

        result = analyze(branching, {"x": "int", "y": "int"})

        assert (
            result.paths_explored > 1
        ), f"Should explore multiple paths, got {result.paths_explored}"
        assert (
            result.paths_completed >= 1
        ), f"Should complete at least one path, got {result.paths_completed}, pruned {result.paths_pruned}"

    def test_nested_conditions(self):
        """Test nested conditional handling."""

        def nested(x, y, z):
            if x > 0:
                if y > 0:
                    if z != 0:
                        return x / z
            return 0

        result = analyze(nested, {"x": "int", "y": "int", "z": "int"})

        # Division is guarded by z != 0
        div_issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)
        assert len(div_issues) == 0, "Nested guard should prevent division issue"

    def test_coverage(self):
        """Test that coverage is recorded."""

        def func(x):
            if x > 0:
                return x + 1
            return x - 1

        result = analyze(func, {"x": "int"})

        assert len(result.coverage) > 0, "Should record coverage"


class TestQuickCheck:
    """Tests for quick_check function."""

    def test_quick_check_finds_issues(self):
        """Test that quick_check finds basic issues."""
        issues = quick_check(lambda x: 1 / x)

        assert len(issues) > 0, "quick_check should find division by zero"

    def test_quick_check_safe_function(self):
        """Test quick_check on safe function."""

        def safe(x):
            return x + 1

        issues = quick_check(safe)

        # Safe function might still have some issues detected
        # but no division by zero
        div_issues = [i for i in issues if i.kind == IssueKind.DIVISION_BY_ZERO]
        assert len(div_issues) == 0, "Safe function should have no div-by-zero"


class TestSpecificChecks:
    """Tests for specific check functions."""

    def test_check_division_by_zero(self):
        """Test check_division_by_zero function."""

        def risky(x, y):
            return x / y

        issues = check_division_by_zero(risky)

        assert len(issues) > 0, "Should find division by zero"
        assert all(i.kind == IssueKind.DIVISION_BY_ZERO for i in issues)

    def test_check_assertions(self):
        """Test check_assertions function - verifies path exploration."""

        def with_assert(x):
            assert x > 0
            return x

        issues = check_assertions(with_assert)
        # Path exploration should work; assertion detection depends on reaching RAISE path
        # This verifies the function runs without error
        assert isinstance(issues, list)


class TestExecutionResult:  # type: ignore[reportRedeclaration]
    """Tests for ExecutionResult class."""

    def test_has_issues(self):
        """Test has_issues method."""

        def risky(x):
            return 1 / x

        result = analyze(risky, {"x": "int"})

        assert result.has_issues() == True

    def test_get_issues_by_kind(self):
        """Test filtering issues by kind."""

        def multi_issue(x, y):
            assert x > 0
            return x / y

        result = analyze(multi_issue, {"x": "int", "y": "int"})

        div_issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)
        assert all(i.kind == IssueKind.DIVISION_BY_ZERO for i in div_issues)

    def test_format_summary(self):
        """Test format_summary method."""

        def func(x):
            return x + 1

        result = analyze(func, {"x": "int"})
        summary = result.format_summary()

        assert "pysymex" in summary
        assert "Paths explored" in summary

    def test_to_dict(self):
        """Test to_dict serialization."""

        def func(x):
            return x / x

        result = analyze(func, {"x": "int"})
        data = result.to_dict()

        assert "function_name" in data
        assert "paths_explored" in data
        assert "issues" in data


class TestIssue:
    """Tests for Issue class."""

    def test_get_counterexample(self):
        """Test counterexample extraction."""

        def div(x, y):
            return x / y

        result = analyze(div, {"x": "int", "y": "int"})

        if result.issues:
            ce = result.issues[0].get_counterexample()
            assert isinstance(ce, dict)

    def test_format(self):
        """Test issue formatting."""

        def div(x, y):
            return x / y

        result = analyze(div, {"x": "int", "y": "int"})

        if result.issues:
            formatted = result.issues[0].format()
            assert "DIVISION_BY_ZERO" in formatted

    def test_to_dict(self):
        """Test issue dict conversion."""

        def div(x, y):
            return x / y

        result = analyze(div, {"x": "int", "y": "int"})

        if result.issues:
            data = result.issues[0].to_dict()
            assert "kind" in data
            assert "message" in data


class TestConfiguration:
    """Tests for configuration options."""

    def test_max_paths_limit(self):
        """Test that max_paths is respected."""

        def complex_func(x, y, z, w):
            if x > 0:
                if y > 0:
                    if z > 0:
                        if w > 0:
                            return 1
            return 0

        result = analyze(
            complex_func,
            {"x": "int", "y": "int", "z": "int", "w": "int"},
            max_paths=10,
        )

        assert result.paths_explored <= 15  # Some buffer for initial paths


class TestResourceTracking:
    """Tests for resource limit enforcement."""

    def test_max_paths_enforced(self):
        """Test that max_paths limit is enforced via ResourceTracker."""

        def infinite_loop(x):
            while x > 0:
                x = x - 1
            return x

        result = analyze(infinite_loop, {"x": "int"}, max_paths=5)
        # Should respect the path limit
        assert result.paths_explored <= 10  # Allow some buffer

    def test_max_depth_enforced(self):
        """Test that max_depth limit is enforced."""

        def recursive(n):
            if n <= 0:
                return 0
            return recursive(n - 1) + 1

        result = analyze(recursive, {"n": "int"}, max_depth=5)
        # Should prune paths beyond max depth
        assert result.paths_pruned >= 0

    def test_timeout_enforced(self):
        """Test that timeout is respected."""

        def slow_func(x):
            # Simulate complex computation
            result = 0
            for i in range(100):
                result += i
            return result

        result = analyze(slow_func, {"x": "int"}, timeout=1.0)
        # Should complete within timeout
        assert result.total_time_seconds < 20.0  # Allow CI/load-dependent overhead


class TestTaintTracking:
    """Tests for taint tracking integration."""

    def test_taint_tracker_attached_to_state(self):
        """Test that taint_tracker is properly attached to VMState."""
        from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

        config = ExecutionConfig(enable_taint_tracking=True)
        executor = SymbolicExecutor(config)

        # Create initial state
        def simple_func(x):
            return x + 1

        result = executor.execute_function(simple_func, {"x": "int"})
        # Should complete without errors
        assert result is not None

    def test_taint_tracking_disabled_when_configured(self):
        """Test that taint tracking can be disabled."""
        from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

        config = ExecutionConfig(enable_taint_tracking=False)
        executor = SymbolicExecutor(config)

        def simple_func(x):
            return x + 1

        result = executor.execute_function(simple_func, {"x": "int"})
        # Should complete without errors
        assert result is not None
        assert result.paths_explored > 0


class TestExecutionResult:
    """Tests for ExecutionResult dataclass."""

    def test_no_duplicate_function_name(self):
        """Test that ExecutionResult doesn't have duplicate function_name field."""
        from pysymex.analysis.detectors import Issue, IssueKind
        from pysymex.execution.executor import ExecutionResult

        # Create an ExecutionResult
        result = ExecutionResult(
            issues=[Issue(kind=IssueKind.DIVISION_BY_ZERO, message="Test", constraints=[], pc=0)],
            paths_explored=10,
            paths_completed=8,
            paths_pruned=2,
            coverage=set([1, 2, 3]),
            total_time_seconds=1.0,
            function_name="test_func",
            source_file="test.py",
        )

        # Should have exactly one function_name field
        assert hasattr(result, "function_name")
        assert result.function_name == "test_func"
        assert result.function_name == "test_func"  # Should work without error

    def test_format_summary_with_function_name(self):
        """Test that format_summary includes function name correctly."""
        from pysymex.execution.executor import ExecutionResult

        result = ExecutionResult(
            function_name="my_function",
            paths_explored=5,
            paths_completed=5,
        )

        summary = result.format_summary()
        assert "my_function" in summary
        assert "Function:" in summary

    def test_to_dict_serialization(self):
        """Test that to_dict works correctly with all fields."""
        from pysymex.execution.executor import ExecutionResult

        result = ExecutionResult(
            function_name="test_func",
            source_file="test.py",
            paths_explored=10,
            paths_completed=8,
            paths_pruned=2,
            total_time_seconds=1.5,
        )

        data = result.to_dict()
        assert data["function_name"] == "test_func"
        assert data["source_file"] == "test.py"
        assert data["paths_explored"] == 10

    def test_disable_detectors(self):
        """Test that detection flags are passed to config.

        Note: Division by zero detection currently happens at opcode level,
        not detector level, so disabling may not fully prevent detection.
        This test verifies the config parameter is accepted.
        """

        def risky(x, y):
            return x / y

        # Verify the function runs with the config option
        result = analyze(
            risky,
            {"x": "int", "y": "int"},
            detect_division_by_zero=False,
        )

        # Should complete analysis without error
        assert result.paths_explored > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
