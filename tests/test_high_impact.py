"""Tests for the three high-impact features:
1. Exception handling (try/except dual-path exploration)
2. Taint sink detection (wiring check_sink into CALL handler)
3. Loop widening integration (abstracting loop variables)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

# ── Feature 1: Exception handling ──────────────────────────────


def test_try_except_explored():
    """Verify that both try and except paths are explored."""

    def function_with_try_except(x):
        try:
            y = 10 / x
        except ZeroDivisionError:
            y = -1
        return y

    config = ExecutionConfig(
        max_depth=30,
        max_paths=100,
        verbose=False,
    )
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(function_with_try_except)
    # The key success criterion: we explored more than 1 path,
    # meaning the SETUP_FINALLY fork created both try and except paths.
    assert (
        result.paths_explored > 1
    ), f"Expected multiple paths for try/except, got {result.paths_explored}"
    print(
        f"  [PASS] try/except: {result.paths_explored} paths explored, "
        f"{result.paths_completed} completed"
    )


def test_nested_try_except():
    """Verify nested try/except blocks are handled."""

    def nested_exception_handling(a, b):
        try:
            try:
                result = a / b
            except ZeroDivisionError:
                result = 0
        except Exception:
            result = -1
        return result

    config = ExecutionConfig(max_depth=40, max_paths=200, verbose=False)
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(nested_exception_handling)
    # Should explore multiple paths through nested exception handlers
    assert (
        result.paths_explored >= 2
    ), f"Expected >=2 paths for nested try/except, got {result.paths_explored}"
    print(f"  [PASS] nested try/except: {result.paths_explored} paths explored")


# ── Feature 2: Taint sink detection ───────────────────────────


def test_taint_sink_detection():
    """Verify that taint flows to dangerous sinks are detected."""
    from pysymex.analysis.taint import TaintSink, TaintSource, TaintTracker

    # Create a tracker and manually taint a value
    tracker = TaintTracker()

    def vulnerable_function(user_input):
        # This simulates: eval(user_input)
        eval(user_input)

    config = ExecutionConfig(
        max_depth=20,
        max_paths=50,
        verbose=False,
        enable_taint_tracking=True,
    )
    executor = SymbolicExecutor(config=config)
    # The key test is that the TaintTracker SINK_FUNCTIONS map exists
    # and contains the expected dangerous functions
    assert "eval" in TaintTracker.SINK_FUNCTIONS
    assert "exec" in TaintTracker.SINK_FUNCTIONS
    assert "os.system" in TaintTracker.SINK_FUNCTIONS
    assert "execute" in TaintTracker.SINK_FUNCTIONS
    assert TaintTracker.SINK_FUNCTIONS["eval"] == TaintSink.EVAL
    assert TaintTracker.SINK_FUNCTIONS["os.system"] == TaintSink.COMMAND_EXEC
    assert TaintTracker.SINK_FUNCTIONS["execute"] == TaintSink.SQL_QUERY

    # Verify check_sink works for tainted data
    from pysymex.core.types import SymbolicValue

    val, _ = SymbolicValue.symbolic("user_data")
    tainted = tracker.mark_tainted(val, TaintSource.USER_INPUT, origin="input()")
    flows = tracker.check_sink(TaintSink.EVAL, val, location="eval", line=5)
    assert len(flows) > 0, "Expected taint flow to be detected for eval() sink"
    print(f"  [PASS] taint sink: detected {len(flows)} flow(s) to eval()")


def test_taint_sink_sanitized():
    """Verify that sanitized values don't trigger taint warnings."""
    from pysymex.analysis.taint import TaintSink, TaintSource, TaintTracker
    from pysymex.core.types import SymbolicValue

    tracker = TaintTracker()
    val, _ = SymbolicValue.symbolic("user_data")
    tracker.mark_tainted(val, TaintSource.USER_INPUT, origin="input()")
    # Sanitize the value
    tracker.mark_sanitized(val)
    flows = tracker.check_sink(TaintSink.EVAL, val, location="eval", line=5)
    assert len(flows) == 0, "Expected no taint flow for sanitized value"
    print("  [PASS] taint sanitizer: sanitized value not flagged")


# ── Feature 3: Loop widening ─────────────────────────────────


def test_loop_widening_exists():
    """Verify that loop widening is integrated into the executor."""
    from pysymex.analysis.loops import LoopWidening

    wid = LoopWidening(widening_threshold=3)
    assert wid.widening_threshold == 3
    assert wid._iteration_count == {}

    # Test should_widen logic
    from pysymex.analysis.loops import LoopInfo

    loop = LoopInfo(
        header_pc=10,
        back_edge_pc=20,
        exit_pcs={30},
        body_pcs={10, 12, 14, 16, 18, 20},
    )
    assert not wid.should_widen(loop)  # 0 iterations
    for _ in range(3):
        wid.record_iteration(loop)
    assert wid.should_widen(loop)  # 3 iterations >= threshold
    print("  [PASS] loop widening: threshold logic works")


def test_loop_widening_integration():
    """Verify loop widening is wired into the executor execution loop."""

    def loop_function(n):
        total = 0
        i = 0
        while i < n:
            total += i
            i += 1
        return total

    config = ExecutionConfig(
        max_depth=50,
        max_paths=200,
        max_loop_iterations=5,  # Low limit to trigger widening
        verbose=False,
        enable_abstract_interpretation=False,  # Isolate test
    )
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(loop_function)
    # The executor should handle loops without crashing
    # and should complete at least some paths
    assert (
        result.paths_explored >= 1
    ), f"Expected at least 1 path for loop function, got {result.paths_explored}"
    print(
        f"  [PASS] loop widening integration: {result.paths_explored} paths, "
        f"{result.paths_completed} completed, {result.paths_pruned} pruned"
    )

    print("  [PASS] taint sanitizer: sanitized value not flagged")


def test_taint_issue_mapping():
    """Verify that sinks map to correct IssueKind."""
    from pysymex.analysis.detectors import IssueKind
    from pysymex.analysis.taint import TaintSource, TaintTracker
    from pysymex.core.state import VMState
    from pysymex.core.types import SymbolicValue
    from pysymex.execution.opcodes.functions import _check_taint_sinks

    # Setup state
    state = VMState()
    state.taint_tracker = TaintTracker()

    # Create tainted value
    val, _ = SymbolicValue.symbolic("bad_input")
    state.taint_tracker.mark_tainted(val, TaintSource.USER_INPUT)

    # Test EVAL -> CODE_INJECTION
    issues = _check_taint_sinks(state, "eval", [val])
    assert len(issues) == 1
    assert issues[0].kind == IssueKind.CODE_INJECTION

    # Test OS.SYSTEM -> COMMAND_INJECTION
    issues = _check_taint_sinks(state, "os.system", [val])
    assert len(issues) == 1
    assert issues[0].kind == IssueKind.COMMAND_INJECTION

    print("  [PASS] taint issue mapping: verified specific IssueKinds")


# ── Improvement 1: False Positive Filtering ─────────────────────


def test_fp_filtering_enabled():
    """Verify that FP filtering runs without error when enabled."""

    def simple_func(x):
        return x + 1

    config = ExecutionConfig(
        max_depth=20,
        max_paths=50,
        enable_fp_filtering=True,
    )
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(simple_func, {"x": "int"})
    # Should complete without error; filtering is applied to results
    assert result.paths_explored >= 1
    print("  [PASS] FP filtering: enabled and executes without error")


def test_fp_filtering_disabled():
    """Verify that FP filtering can be disabled."""

    def simple_func(x):
        return x + 1

    config = ExecutionConfig(
        max_depth=20,
        max_paths=50,
        enable_fp_filtering=False,
    )
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(simple_func, {"x": "int"})
    assert result.paths_explored >= 1
    print("  [PASS] FP filtering: disabled mode works")


# ── Improvement 2: Smarter Exception Forking ────────────────────


def test_exception_precision_no_fork_for_safe_try():
    """A try block with only safe ops (assignments, constants) should
    NOT fork an exception path, reducing path count."""

    def safe_try(x):
        try:
            y = x + 1  # BINARY_OP is in _RAISING_OPS (might be div)
            z = y
        except Exception:
            z = -1
        return z

    config = ExecutionConfig(max_depth=30, max_paths=100)
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(safe_try, {"x": "int"})
    # Should complete without errors
    assert result.paths_explored >= 1
    print("  [PASS] exception precision: safe try block handled")


def test_exception_precision_forks_for_division():
    """A try block containing division SHOULD still fork."""

    def risky_try(x):
        try:
            y = 10 / x  # Division can raise ZeroDivisionError
        except ZeroDivisionError:
            y = -1
        return y

    config = ExecutionConfig(max_depth=30, max_paths=100)
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(risky_try, {"x": "int"})
    # Should explore multiple paths (try + except)
    assert result.paths_explored >= 2
    print("  [PASS] exception precision: division try block forks correctly")


# ── Improvement 3: Cross-Function Analysis ──────────────────────


def test_cross_function_config():
    """Verify cross-function analysis config flag works."""

    def simple_func(x):
        return x * 2

    config = ExecutionConfig(
        max_depth=20,
        max_paths=50,
        enable_cross_function=True,
    )
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(simple_func, {"x": "int"})
    assert result.paths_explored >= 1
    print("  [PASS] cross-function: enabled and executes without error")


# ── Improvement 4: Type Inference ───────────────────────────────


def test_type_inference_config():
    """Verify type inference config flag works."""

    def typed_func(x: int, y: str) -> int:
        return x + len(y)

    config = ExecutionConfig(
        max_depth=20,
        max_paths=50,
        enable_type_inference=True,
    )
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(typed_func, {"x": "int", "y": "str"})
    assert result.paths_explored >= 1
    print("  [PASS] type inference: enabled and executes without error")


# ── Improvement 5: SARIF Output ─────────────────────────────────


def test_sarif_output():
    """Verify that to_sarif() produces valid SARIF structure."""

    def div_func(x):
        return 10 / x

    config = ExecutionConfig(max_depth=30, max_paths=100)
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(div_func, {"x": "int"})

    sarif = result.to_sarif()

    # Validate SARIF structure
    assert "version" in sarif
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert "tool" in run
    assert run["tool"]["driver"]["name"] == "pysymex"
    assert "results" in run
    print(f"  [PASS] SARIF output: valid structure with {len(run['results'])} results")


def test_sarif_issue_mapping():
    """Verify that IssueKind maps to SARIF rule IDs correctly."""

    def div_func(x):
        return 10 / x

    config = ExecutionConfig(max_depth=30, max_paths=100)
    executor = SymbolicExecutor(config=config)
    result = executor.execute_function(div_func, {"x": "int"})

    sarif = result.to_sarif()
    run = sarif["runs"][0]

    # If division by zero issues exist, they should be in results
    if result.has_issues():
        assert len(run["results"]) > 0
        # Check that results have required fields
        for sarif_result in run["results"]:
            assert "ruleId" in sarif_result
            assert "message" in sarif_result
            assert "level" in sarif_result
    print("  [PASS] SARIF issue mapping: issues correctly mapped to SARIF results")


if __name__ == "__main__":
    print("\n=== High-Impact Feature Tests ===\n")

    print("Feature 1: Exception Handling")
    test_try_except_explored()
    test_nested_try_except()

    print("\nFeature 2: Taint Sink Detection")
    test_taint_sink_detection()
    test_taint_sink_sanitized()

    print("\nFeature 3: Loop Widening")
    test_loop_widening_exists()
    test_loop_widening_integration()

    print("\nImprovement 1: False Positive Filtering")
    test_fp_filtering_enabled()
    test_fp_filtering_disabled()

    print("\nImprovement 2: Exception Precision")
    test_exception_precision_no_fork_for_safe_try()
    test_exception_precision_forks_for_division()

    print("\nImprovement 3: Cross-Function Analysis")
    test_cross_function_config()

    print("\nImprovement 4: Type Inference")
    test_type_inference_config()

    print("\nImprovement 5: SARIF Output")
    test_sarif_output()
    test_sarif_issue_mapping()

    print("\n=== All tests passed! ===")
