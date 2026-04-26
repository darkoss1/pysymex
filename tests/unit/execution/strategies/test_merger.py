from __future__ import annotations

import dis

import z3

from pysymex.core.state import VMState
from pysymex.execution.strategies.merger import (
    AbstractVarInfo,
    MergePolicy,
    MergeStatistics,
    StateMerger,
    create_state_merger,
)


class TestMergePolicy:
    """Test suite for pysymex.execution.strategies.merger.MergePolicy."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        names = {item.name for item in MergePolicy}
        assert "CONSERVATIVE" in names
        assert "MODERATE" in names
        assert "AGGRESSIVE" in names


class TestMergeStatistics:
    """Test suite for pysymex.execution.strategies.merger.MergeStatistics."""

    def test_reduction_ratio(self) -> None:
        """Test reduction_ratio behavior."""
        stats = MergeStatistics(states_before_merge=10, states_after_merge=4)
        assert abs(stats.reduction_ratio - 0.6) < 1e-9


class TestAbstractVarInfo:
    """Test suite for pysymex.execution.strategies.merger.AbstractVarInfo."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        info = AbstractVarInfo(interval_lo=0, interval_hi=10, may_be_none=False, must_be_type="int")
        assert info.interval_lo == 0
        assert info.interval_hi == 10
        assert info.must_be_type == "int"


class TestStateMerger:
    """Test suite for pysymex.execution.strategies.merger.StateMerger."""

    def test_set_join_points(self) -> None:
        """Test set_join_points behavior."""
        merger = StateMerger()
        merger.set_join_points({1, 2})
        assert merger.is_join_point(2) is True

    def test_detect_join_points(self) -> None:
        """Test detect_join_points behavior."""
        code = compile("x = 0\nif x:\n    y = 1\nelse:\n    y = 2\n", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        merger = StateMerger()
        join_points = merger.detect_join_points(instructions)
        assert isinstance(join_points, set)

    def test_is_join_point(self) -> None:
        """Test is_join_point behavior."""
        merger = StateMerger()
        merger.set_join_points({5})
        assert merger.is_join_point(5) is True
        assert merger.is_join_point(1) is False

    def test_should_merge(self) -> None:
        """Test should_merge behavior."""
        merger = StateMerger(max_constraints_for_merge=2)
        merger.set_join_points({7})
        state = VMState(pc=7, path_constraints=[z3.Bool("a")])
        assert merger.should_merge(state) is True

    def test_add_state_for_merge(self) -> None:
        """Test add_state_for_merge behavior."""
        merger = StateMerger()
        state = VMState(pc=1)
        added = merger.add_state_for_merge(state)
        assert added is state
        assert merger.stats.states_before_merge == 1

    def test_get_pending_states(self) -> None:
        """Test get_pending_states behavior."""
        merger = StateMerger()
        state = VMState(pc=3)
        merger.add_state_for_merge(state)
        pending = merger.get_pending_states(3)
        assert len(pending) == 1

    def test_clear_pending(self) -> None:
        """Test clear_pending behavior."""
        merger = StateMerger()
        merger.add_state_for_merge(VMState(pc=4))
        merger.clear_pending(4)
        assert merger.get_pending_states(4) == []

    def test_reset(self) -> None:
        """Test reset behavior."""
        merger = StateMerger()
        merger.add_state_for_merge(VMState(pc=9))
        merger.reset()
        assert merger.get_pending_states(9) == []
        assert merger.stats.states_before_merge == 0


def test_create_state_merger() -> None:
    """Test create_state_merger behavior."""
    merger = create_state_merger(policy="aggressive", max_constraints=11, similarity_threshold=0.8)
    assert isinstance(merger, StateMerger)
    assert merger.policy is MergePolicy.AGGRESSIVE
    assert merger.max_constraints_for_merge == 11


class TestMergerHelpers:
    """Test suite for pysymex.execution.strategies.merger helper functions."""

    def test_is_any_symbolic_with_symbolic_value(self) -> None:
        """Test that _is_any_symbolic returns True for SymbolicValue."""
        from pysymex.core.types.scalars import SymbolicValue

        val = SymbolicValue.from_const(42)
        from pysymex.execution.strategies.merger import _is_any_symbolic  # type: ignore[private]

        assert _is_any_symbolic(val) is True

    def test_is_any_symbolic_with_non_symbolic(self) -> None:
        """Test that _is_any_symbolic returns False for non-symbolic types."""
        from pysymex.execution.strategies.merger import _is_any_symbolic  # type: ignore[private]

        assert _is_any_symbolic(42) is False
        assert _is_any_symbolic("string") is False
        assert _is_any_symbolic(None) is False

    def test_is_conditional_mergeable_with_callable(self) -> None:
        """Test that _is_conditional_mergeable returns True for callable conditional_merge."""
        from pysymex.core.types.scalars import SymbolicValue

        val = SymbolicValue.from_const(42)
        from pysymex.execution.strategies.merger import _is_conditional_mergeable  # type: ignore[private]

        assert _is_conditional_mergeable(val) is True

    def test_is_conditional_mergeable_without_callable(self) -> None:
        """Test that _is_conditional_mergeable returns False for non-callable."""
        from pysymex.execution.strategies.merger import _is_conditional_mergeable  # type: ignore[private]

        assert _is_conditional_mergeable(42) is False
        assert _is_conditional_mergeable("string") is False

    def test_is_stack_value_with_valid_types(self) -> None:
        """Test that _is_stack_value returns True for valid stack value types."""
        from pysymex.execution.strategies.merger import _is_stack_value  # type: ignore[private]

        assert _is_stack_value(None) is True
        assert _is_stack_value(42) is True
        assert _is_stack_value(True) is True
        assert _is_stack_value("string") is True
        assert _is_stack_value(3.14) is True
        assert _is_stack_value(b"bytes") is True
        assert _is_stack_value(int) is True
        assert _is_stack_value([1, 2, 3]) is True
        assert _is_stack_value((1, 2, 3)) is True
        assert _is_stack_value({"key": "value"}) is True
        assert _is_stack_value(lambda: None) is True

    def test_is_stack_value_with_invalid_types(self) -> None:
        """Test that _is_stack_value returns False for invalid stack value types."""
        from pysymex.execution.strategies.merger import _is_stack_value  # type: ignore[private]

        class CustomClass:
            pass

        assert _is_stack_value(CustomClass()) is False

    def test_as_string_object_mapping_with_mapping(self) -> None:
        """Test that _as_string_object_mapping converts valid mapping to dict."""
        from pysymex.execution.strategies.merger import _as_string_object_mapping  # type: ignore[private]

        mapping: dict[str, int] = {"key": 42}
        result = _as_string_object_mapping(mapping)
        assert result is not None
        assert result == {"key": 42}

    def test_as_string_object_mapping_with_none(self) -> None:
        """Test that _as_string_object_mapping returns empty dict for None."""
        from pysymex.execution.strategies.merger import _as_string_object_mapping  # type: ignore[private]

        result = _as_string_object_mapping(None)
        assert result is not None
        assert result == {}
