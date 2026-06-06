"""Frontier stress tests for symbolic execution edge-case semantics."""

from __future__ import annotations


from pysymex.analysis.detectors import IssueKind
from pysymex.execution.executors.async_support.runner import (
    AsyncSymbolicExecutor,
    SymbolicEventLoop,
)
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.config.settings import ExecutionConfig


def _build_executor(
    *, use_loop_analysis: bool = False, max_loop_iterations: int = 10
) -> SymbolicExecutor:
    """Create a deterministic SymbolicExecutor for frontier tests."""
    config = ExecutionConfig(
        max_paths=256,
        max_depth=128,
        max_iterations=16384,
        timeout_seconds=20.0,
        enable_cross_function=False,
        enable_type_inference=False,
        use_loop_analysis=use_loop_analysis,
        enable_caching=False,
        enable_fp_filtering=False,
        enable_solver_cache=False,
        max_loop_iterations=max_loop_iterations,
        verbose=False,
    )
    return SymbolicExecutor(config=config)


def _build_async_executor() -> AsyncSymbolicExecutor:
    """Create a deterministic AsyncSymbolicExecutor for await/interleaving tests."""
    config = ExecutionConfig(
        max_paths=256,
        max_depth=128,
        max_iterations=16384,
        timeout_seconds=20.0,
        enable_cross_function=False,
        enable_type_inference=False,
        use_loop_analysis=False,
        enable_caching=False,
        enable_fp_filtering=False,
        enable_solver_cache=False,
        max_interleavings=32,
        verbose=False,
    )
    return AsyncSymbolicExecutor(config=config)


def test_symbolic_dictionary_key_forks_match_and_miss_paths() -> None:
    """Verify symbolic dictionary-key writes fork equality and non-equality paths."""

    def symbolic_dict_branch(key: str) -> int:
        """Branch on value inserted through a symbolic dictionary key."""
        mapping: dict[str, int] = {}
        mapping[key] = 1
        if mapping.get("a", 0) == 1:
            return 1
        return 0

    executor = _build_executor()
    result = executor.execute_function(symbolic_dict_branch, symbolic_args={"key": "str"})
    assert result.paths_completed >= 2


def test_symbolic_dictionary_key_get_has_no_attribute_false_positive() -> None:
    """Verify symbolic dictionary get-path does not emit spurious ATTRIBUTE_ERROR."""

    def symbolic_dict_branch(key: str) -> int:
        """Branch on value inserted through a symbolic dictionary key."""
        mapping: dict[str, int] = {}
        mapping[key] = 1
        if mapping.get("a", 0) == 1:
            return 1
        return 0

    executor = _build_executor()
    result = executor.execute_function(symbolic_dict_branch, symbolic_args={"key": "str"})
    assert any(issue.kind == IssueKind.ATTRIBUTE_ERROR for issue in result.issues) is False


def test_dunder_add_override_drives_division_semantics() -> None:
    """Verify __add__ override affects arithmetic and can trigger divide-by-zero."""

    class ZeroAdd:
        """Object whose __add__ override always returns zero."""

        def __add__(self, _other: object) -> int:
            """Return zero for all additions."""
            return 0

    def custom_add_driven_division() -> float:
        """Divide by result of overridden addition."""
        value = ZeroAdd()
        return 10.0 / (value + 5)

    executor = _build_executor()
    result = executor.execute_function(custom_add_driven_division)
    assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)


def test_dunder_getattribute_override_avoids_spurious_attribute_error() -> None:
    """Verify __getattribute__ override supports dynamic attribute resolution."""

    class DynamicGetAttribute:
        """Object providing attribute x through __getattribute__ override."""

        def __getattribute__(self, name: str) -> int:
            """Resolve x and reject all other names."""
            if name == "x":
                return 42
            raise AttributeError(name)

    def read_dynamic_attribute() -> int:
        """Read dynamically resolved attribute."""
        obj = DynamicGetAttribute()
        return obj.x

    executor = _build_executor()
    result = executor.execute_function(read_dynamic_attribute)
    assert any(issue.kind == IssueKind.ATTRIBUTE_ERROR for issue in result.issues) is False


def test_dunder_eq_override_remains_single_path_when_concrete() -> None:
    """Verify concrete __eq__ override does not fork impossible alternate branch."""

    class AlwaysEqual:
        """Object whose equality override is concretely True."""

        def __eq__(self, _other: object) -> bool:
            """Return True for all comparisons."""
            return True

    def eq_override_branch() -> int:
        """Branch on equality that is concretely True."""
        if AlwaysEqual() == 123:
            return 1
        return 0

    executor = _build_executor()
    result = executor.execute_function(eq_override_branch)
    assert result.paths_completed == 1


def test_symbolic_loop_bound_prunes_with_iteration_limit() -> None:
    """Verify symbolic loop bounds are contained by loop-iteration limiting."""

    def bounded_symbolic_loop(value: int) -> int:
        """Decrement symbolic value until non-positive."""
        while value > 0:
            value -= 1
        return value

    executor = _build_executor(use_loop_analysis=True, max_loop_iterations=4)
    result = executor.execute_function(bounded_symbolic_loop, symbolic_args={"value": "int"})
    assert result.paths_pruned > 0


def test_async_executor_handles_symbolic_await_branch() -> None:
    """Verify AsyncSymbolicExecutor executes coroutine code with symbolic branch + await."""

    async def increment_async(value: int) -> int:
        """Return incremented value from async helper."""
        return value + 1

    async def branch_and_await(value: int) -> int:
        """Await helper only on one symbolic branch."""
        if value > 0:
            awaited = await increment_async(value)
            return awaited
        return value

    executor = _build_async_executor()
    result = executor.execute_function(branch_and_await, symbolic_args={"value": "int"})
    assert result.paths_completed >= 1


def test_symbolic_event_loop_detects_two_node_await_cycle() -> None:
    """Verify await-cycle detection reports one cycle for two mutually awaiting coroutines."""
    loop = SymbolicEventLoop(max_interleavings=8)
    first = loop.create_coroutine("first")
    second = loop.create_coroutine("second")
    first.awaiting = second.coro_id
    second.awaiting = first.coro_id
    cycles = loop.detect_await_cycles()
    assert len(cycles) == 1


def test_min_max_value_error_detector_safe_with_default_or_multi_args() -> None:
    """Verify ValueErrorDetector does not falsely report ValueError for min/max with default, multi-args, or custom subclass."""

    class WeirdList(list[int]):
        def __bool__(self) -> bool:
            return False

    def run_min_max() -> int:
        a = min([], default=0)
        b = min(1, 2)
        c = min(WeirdList([1]))
        return a + b + c

    executor = _build_executor()
    result = executor.execute_function(run_min_max)
    assert not any(issue.kind == IssueKind.VALUE_ERROR for issue in result.issues)
