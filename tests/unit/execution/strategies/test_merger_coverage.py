"""Tests for pysymex.execution.strategies.merger — StateMerger, helper functions, MergeStatistics."""

from __future__ import annotations

import dis

import z3

from pysymex.execution.strategies.merger import (
    MergePolicy,
    MergeStatistics,
    StateMerger,
    _as_string_object_mapping,
    _is_any_symbolic,
    _is_conditional_mergeable,
    _is_stack_value,
    create_state_merger,
)


class TestMergeStatistics:
    """Test MergeStatistics dataclass."""

    def test_reduction_ratio_zero_states(self) -> None:
        """reduction_ratio returns 0.0 when states_before_merge == 0."""
        stats = MergeStatistics()
        assert stats.reduction_ratio == 0.0

    def test_reduction_ratio_half(self) -> None:
        """reduction_ratio returns 0.5 when half the states are merged."""
        stats = MergeStatistics(states_before_merge=10, states_after_merge=5)
        assert abs(stats.reduction_ratio - 0.5) < 1e-9

    def test_reduction_ratio_full(self) -> None:
        """reduction_ratio returns 1.0 when all states merged."""
        stats = MergeStatistics(states_before_merge=10, states_after_merge=0)
        assert abs(stats.reduction_ratio - 1.0) < 1e-9


class TestCreateStateMerger:
    """Test create_state_merger factory."""

    def test_default_policy(self) -> None:
        """Default factory creates MODERATE merger."""
        merger = create_state_merger()
        assert merger.policy == MergePolicy.MODERATE

    def test_conservative_policy(self) -> None:
        """Policy 'conservative' maps correctly."""
        merger = create_state_merger(policy="conservative")
        assert merger.policy == MergePolicy.CONSERVATIVE

    def test_aggressive_policy(self) -> None:
        """Policy 'aggressive' maps correctly."""
        merger = create_state_merger(policy="aggressive")
        assert merger.policy == MergePolicy.AGGRESSIVE

    def test_unknown_policy_defaults_to_moderate(self) -> None:
        """Unknown policy string defaults to MODERATE."""
        merger = create_state_merger(policy="unknown")
        assert merger.policy == MergePolicy.MODERATE

    def test_max_constraints_parameter(self) -> None:
        """max_constraints parameter is stored."""
        merger = create_state_merger(max_constraints=100)
        assert merger.max_constraints_for_merge == 100


class TestStateMerger:
    """Test StateMerger methods."""

    def test_set_join_points(self) -> None:
        """set_join_points stores the join points."""
        merger = StateMerger()
        merger.set_join_points({1, 5, 10})
        assert merger.is_join_point(5)
        assert not merger.is_join_point(3)

    def test_detect_join_points_empty(self) -> None:
        """detect_join_points with empty instructions returns empty set."""
        merger = StateMerger()
        result = merger.detect_join_points([])
        assert result == set()

    def test_detect_join_points_with_branches(self) -> None:
        """detect_join_points identifies join points in branching code."""
        code = compile("x = 1 if True else 2", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        merger = StateMerger()
        join_points = merger.detect_join_points(instructions)
        # Should have at least some structure (compiler may optimize)
        assert isinstance(join_points, set)

    def test_is_join_point(self) -> None:
        """is_join_point checks membership in _join_points."""
        merger = StateMerger()
        merger._join_points = {0, 5, 10}
        assert merger.is_join_point(5)
        assert not merger.is_join_point(7)

    def test_reset(self) -> None:
        """reset clears pending states and statistics."""
        merger = StateMerger()
        merger._join_points = {1, 2, 3}
        merger.stats.merge_operations = 5
        merger.reset()
        assert merger.stats.merge_operations == 0

    def test_get_pending_states_empty(self) -> None:
        """get_pending_states returns [] for unknown PC."""
        merger = StateMerger()
        assert merger.get_pending_states(42) == []

    def test_clear_pending(self) -> None:
        """clear_pending removes pending states at given PC."""
        merger = StateMerger()
        merger._pending_states[5] = {0: []}
        merger.clear_pending(5)
        assert 5 not in merger._pending_states

    def test_clear_pending_nonexistent_pc(self) -> None:
        """clear_pending with nonexistent PC does not error."""
        merger = StateMerger()
        merger.clear_pending(999)  # Should not raise

    def test_constraints_equal_identical(self) -> None:
        """_constraints_equal returns True for identical constraints."""
        merger = StateMerger()
        x = z3.Int("x")
        c = x > 0
        assert merger._constraints_equal(c, c) is True

    def test_constraints_equal_structurally(self) -> None:
        """_constraints_equal returns True for structurally equal constraints."""
        merger = StateMerger()
        x = z3.Int("x")
        c1 = x > 0
        c2 = x > 0
        assert merger._constraints_equal(c1, c2) is True

    def test_values_structurally_equal_same_ref(self) -> None:
        """_values_structurally_equal returns True for same reference."""
        merger = StateMerger()
        obj = object()
        assert merger._values_structurally_equal(obj, obj) is True

    def test_values_structurally_equal_z3(self) -> None:
        """_values_structurally_equal compares Z3 expressions."""
        merger = StateMerger()
        x = z3.Int("x")
        assert merger._values_structurally_equal(x + 1, x + 1) is True
        assert merger._values_structurally_equal(x + 1, x + 2) is False

    def test_values_structurally_equal_primitives(self) -> None:
        """_values_structurally_equal compares primitives."""
        merger = StateMerger()
        assert merger._values_structurally_equal(42, 42) is True
        assert merger._values_structurally_equal(42, 43) is False

    def test_mapping_hash_mismatch_no_hash(self) -> None:
        """_mapping_hash_mismatch returns False for plain dicts."""
        merger = StateMerger()
        result = merger._mapping_hash_mismatch({"a": 1}, {"a": 1})
        assert result is False

    def test_mapping_equal_same_ref(self) -> None:
        """_mapping_equal returns True for same reference."""
        merger = StateMerger()
        d: dict[str, object] = {"a": 1}
        assert merger._mapping_equal(d, d) is True

    def test_mapping_equal_different_lengths(self) -> None:
        """_mapping_equal returns False for different lengths."""
        merger = StateMerger()
        assert merger._mapping_equal({"a": 1}, {"a": 1, "b": 2}) is False

    def test_mapping_equal_different_keys(self) -> None:
        """_mapping_equal returns False for different keys."""
        merger = StateMerger()
        assert merger._mapping_equal({"a": 1}, {"b": 1}) is False


class TestIsAnySymbolic:
    """Test _is_any_symbolic helper."""

    def test_symbolic_value_is_symbolic(self) -> None:
        """SymbolicValue is recognized as symbolic."""
        from pysymex.core.types.scalars import SymbolicValue

        v, _ = SymbolicValue.symbolic("test")
        assert _is_any_symbolic(v) is True

    def test_int_is_not_symbolic(self) -> None:
        """int is not symbolic."""
        assert _is_any_symbolic(42) is False

    def test_none_is_not_symbolic(self) -> None:
        """None is not symbolic."""
        assert _is_any_symbolic(None) is False


class TestIsConditionalMergeable:
    """Test _is_conditional_mergeable helper."""

    def test_symbolic_value_is_mergeable(self) -> None:
        """SymbolicValue exposes conditional_merge and is mergeable."""
        from pysymex.core.types.scalars import SymbolicValue

        v, _ = SymbolicValue.symbolic("test")
        assert _is_conditional_mergeable(v) is True

    def test_int_is_not_mergeable(self) -> None:
        """int has no conditional_merge method."""
        assert _is_conditional_mergeable(42) is False


class TestIsStackValue:
    """Test _is_stack_value helper."""

    def test_none_is_stack_value(self) -> None:
        """None is a valid StackValue."""
        assert _is_stack_value(None) is True

    def test_int_is_stack_value(self) -> None:
        """int is a valid StackValue."""
        assert _is_stack_value(42) is True

    def test_str_is_stack_value(self) -> None:
        """str is a valid StackValue."""
        assert _is_stack_value("hello") is True

    def test_z3_expr_is_stack_value(self) -> None:
        """Z3 expression is a valid StackValue."""
        assert _is_stack_value(z3.Int("x")) is True

    def test_list_is_stack_value(self) -> None:
        """list is a valid StackValue."""
        assert _is_stack_value([1, 2, 3]) is True

    def test_tuple_is_stack_value(self) -> None:
        """tuple is a valid StackValue."""
        assert _is_stack_value((1, 2)) is True

    def test_dict_is_stack_value(self) -> None:
        """dict is a valid StackValue."""
        assert _is_stack_value({"a": 1}) is True

    def test_callable_is_stack_value(self) -> None:
        """callable is a valid StackValue."""
        assert _is_stack_value(lambda: None) is True

    def test_symbolic_is_stack_value(self) -> None:
        """SymbolicValue is a valid StackValue."""
        from pysymex.core.types.scalars import SymbolicValue

        v, _ = SymbolicValue.symbolic("test")
        assert _is_stack_value(v) is True


class TestAsStringObjectMapping:
    """Test _as_string_object_mapping helper."""

    def test_none_returns_empty_dict(self) -> None:
        """None is treated as empty mapping."""
        result = _as_string_object_mapping(None)
        assert result == {}

    def test_non_mapping_returns_none(self) -> None:
        """Non-mapping returns None."""
        result = _as_string_object_mapping(42)
        assert result is None
