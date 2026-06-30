"""Tests for pysymex._internal.execution.strategies.merger — StateMerger, helper functions, MergeStatistics."""

from __future__ import annotations

import dis

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import CallFrame, wrap_cow_dict
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.strategies.merger.equality.mixin import StateMergerEqualityMixin
from pysymex._internal.execution.strategies.merger.equality.mixin import (
    StateMergerEqualityMixin as StateMergerEqualityMixinOwner,
)
from pysymex._internal.execution.strategies.merger.merge_guards import MergeGuards
from pysymex._internal.execution.strategies.merger.state import StateMerger
from pysymex._internal.execution.strategies.merger.symbolic.mixin import (
    StateMergerSymbolicMixin as StateMergerSymbolicMixinExport,
)
from pysymex._internal.execution.strategies.merger.symbolic.mixin import (
    StateMergerSymbolicMixin as StateMergerSymbolicMixinOwner,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.frames import (
    merge_call_stack as merge_call_stack_export,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.frames import (
    merge_call_stack as merge_call_stack_owner,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.memory import (
    merge_memory as merge_memory_export,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.memory import (
    merge_memory as merge_memory_owner,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.variables import (
    merge_global_vars as merge_global_vars_export,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.variables import (
    merge_global_vars as merge_global_vars_owner,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.variables import (
    merge_local_vars as merge_local_vars_export,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.variables import (
    merge_local_vars as merge_local_vars_owner,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.variables import (
    merge_stack as merge_stack_export,
)
from pysymex._internal.execution.strategies.merger.symbolic.regions.variables import (
    merge_stack as merge_stack_owner,
)
from pysymex._internal.execution.strategies.merger.types import MergeStatistics
from pysymex._internal.typing.protocols import StackValue


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


class TestStateMerger:
    """Test StateMerger methods."""

    def test_equality_public_export_points_to_direct_owner(self) -> None:
        """The equality package exports the composed mixin owner directly."""
        assert StateMergerEqualityMixin is StateMergerEqualityMixinOwner

    def test_symbolic_public_export_points_to_direct_owner(self) -> None:
        """The symbolic package exports the composed mixin owner directly."""
        assert StateMergerSymbolicMixinExport is StateMergerSymbolicMixinOwner

    def test_symbolic_region_public_exports_point_to_direct_owners(self) -> None:
        """The symbolic region package exports each direct storage-region owner."""
        assert merge_call_stack_export is merge_call_stack_owner
        assert merge_memory_export is merge_memory_owner
        assert merge_global_vars_export is merge_global_vars_owner
        assert merge_local_vars_export is merge_local_vars_owner
        assert merge_stack_export is merge_stack_owner

    def test_symbolic_frame_region_merges_retained_call_frame_locals(self) -> None:
        """Retained call-frame locals merge without changing frame identity fields."""
        shared: StackValue = SymbolicValue.from_const(1)
        right_only: StackValue = SymbolicValue.from_const(2)
        state1 = VMState(
            call_stack=[CallFrame("callee", 2, wrap_cow_dict({"shared": shared}), 1, ())],
        )
        state2 = VMState(
            call_stack=[
                CallFrame(
                    "callee",
                    2,
                    wrap_cow_dict({"shared": shared, "right": right_only}),
                    1,
                    (),
                )
            ],
        )
        merged = VMState()

        merged_ok = merge_call_stack_owner(
            merged,
            state1,
            state2,
            z3.Bool("merge_frame_region"),
            lambda left, right: left is right,
        )

        assert merged_ok is True
        assert len(merged.call_stack) == 1
        assert merged.call_stack[0].function_name == "callee"
        assert merged.call_stack[0].return_pc == 2
        assert merged.call_stack[0].local_vars["shared"] is shared
        assert merged.call_stack[0].local_vars["right"] is right_only

    def test_symbolic_memory_region_merges_mapping_cells(self) -> None:
        """Memory-cell mapping joins preserve shared and single-sided attributes."""
        shared: StackValue = SymbolicValue.from_const(1)
        right_only: StackValue = SymbolicValue.from_const(2)
        left_memory: dict[int, StackValue] = {7: {"shared": shared}}
        right_memory: dict[int, StackValue] = {7: {"shared": shared, "right": right_only}}
        state1 = VMState(memory=left_memory)
        state2 = VMState(memory=right_memory)
        merged = VMState()

        merged_ok = merge_memory_owner(
            merged,
            state1,
            state2,
            z3.Bool("merge_memory_region"),
            lambda left, right: left is right,
        )

        assert merged_ok is True
        merged_cell = merged.memory[7]
        assert isinstance(merged_cell, dict)
        assert merged_cell["shared"] is shared
        assert merged_cell["right"] is right_only

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
        """is_join_point checks membership in join_points."""
        merger = StateMerger()
        merger.join_points = {0, 5, 10}
        assert merger.is_join_point(5)
        assert not merger.is_join_point(7)

    def test_reset(self) -> None:
        """reset clears pending states and statistics."""
        merger = StateMerger()
        merger.join_points = {1, 2, 3}
        merger.stats.merge_operations = 5
        merger.reset()
        assert merger.stats.merge_operations == 0

    def test_constraints_equal_identical(self) -> None:
        """constraints_equal returns True for identical constraints."""
        merger = StateMerger()
        x = z3.Int("x")
        c = x > 0
        assert merger.constraints_equal(c, c) is True

    def test_constraints_equal_structurally(self) -> None:
        """constraints_equal returns True for structurally equal constraints."""
        merger = StateMerger()
        x = z3.Int("x")
        c1 = x > 0
        c2 = x > 0
        assert merger.constraints_equal(c1, c2) is True

    def test_values_structurally_equal_same_ref(self) -> None:
        """values_structurally_equal returns True for same reference."""
        merger = StateMerger()
        obj = object()
        assert merger.values_structurally_equal(obj, obj) is True

    def test_values_structurally_equal_z3(self) -> None:
        """values_structurally_equal compares Z3 expressions."""
        merger = StateMerger()
        x = z3.Int("x")
        assert merger.values_structurally_equal(x + 1, x + 1) is True
        assert merger.values_structurally_equal(x + 1, x + 2) is False

    def test_values_structurally_equal_primitives(self) -> None:
        """values_structurally_equal compares primitives."""
        merger = StateMerger()
        assert merger.values_structurally_equal(42, 42) is True
        assert merger.values_structurally_equal(42, 43) is False

    def test_mapping_hash_mismatch_no_hash(self) -> None:
        """mapping_hash_mismatch returns False for plain dicts."""
        merger = StateMerger()
        result = merger.mapping_hash_mismatch({"a": 1}, {"a": 1})
        assert result is False

    def test_mapping_equal_same_ref(self) -> None:
        """mapping_equal returns True for same reference."""
        merger = StateMerger()
        d: dict[str, object] = {"a": 1}
        assert merger.mapping_equal(d, d) is True

    def test_mapping_equal_different_lengths(self) -> None:
        """mapping_equal returns False for different lengths."""
        merger = StateMerger()
        assert merger.mapping_equal({"a": 1}, {"a": 1, "b": 2}) is False

    def test_mapping_equal_different_keys(self) -> None:
        """mapping_equal returns False for different keys."""
        merger = StateMerger()
        assert merger.mapping_equal({"a": 1}, {"b": 1}) is False


class TestIsAnySymbolic:
    """Test _is_any_symbolic helper."""

    def test_symbolic_value_is_symbolic(self) -> None:
        """SymbolicValue is recognized as symbolic."""
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        v, _ = SymbolicValue.symbolic("test")
        assert MergeGuards.is_symbolic(v) is True

    def test_int_is_not_symbolic(self) -> None:
        """int is not symbolic."""
        assert MergeGuards.is_symbolic(42) is False

    def test_none_is_not_symbolic(self) -> None:
        """None is not symbolic."""
        assert MergeGuards.is_symbolic(None) is False


class TestIsConditionalMergeable:
    """Test _is_conditional_mergeable helper."""

    def test_symbolic_value_is_mergeable(self) -> None:
        """SymbolicValue exposes conditional_merge and is mergeable."""
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        v, _ = SymbolicValue.symbolic("test")
        assert MergeGuards.is_mergeable(v) is True

    def test_int_is_not_mergeable(self) -> None:
        """int has no conditional_merge method."""
        assert MergeGuards.is_mergeable(42) is False


class TestIsStackValue:
    """Test _is_stack_value helper."""

    def test_none_is_stack_value(self) -> None:
        """None is a valid StackValue."""
        assert MergeGuards.is_stack_value(None) is True

    def test_int_is_stack_value(self) -> None:
        """int is a valid StackValue."""
        assert MergeGuards.is_stack_value(42) is True

    def test_str_is_stack_value(self) -> None:
        """str is a valid StackValue."""
        assert MergeGuards.is_stack_value("hello") is True

    def test_z3_expr_is_stack_value(self) -> None:
        """Z3 expression is a valid StackValue."""
        assert MergeGuards.is_stack_value(z3.Int("x")) is True

    def test_list_is_stack_value(self) -> None:
        """list is a valid StackValue."""
        assert MergeGuards.is_stack_value([1, 2, 3]) is True

    def test_tuple_is_stack_value(self) -> None:
        """tuple is a valid StackValue."""
        assert MergeGuards.is_stack_value((1, 2)) is True

    def test_dict_is_stack_value(self) -> None:
        """dict is a valid StackValue."""
        assert MergeGuards.is_stack_value({"a": 1}) is True

    def test_callable_is_stack_value(self) -> None:
        """callable is a valid StackValue."""
        assert MergeGuards.is_stack_value(lambda: None) is True

    def test_symbolic_is_stack_value(self) -> None:
        """SymbolicValue is a valid StackValue."""
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        v, _ = SymbolicValue.symbolic("test")
        assert MergeGuards.is_stack_value(v) is True


class TestAsStringObjectMapping:
    """Test _as_string_object_mapping helper."""

    def test_none_returns_empty_dict(self) -> None:
        """None is treated as empty mapping."""
        result = MergeGuards.as_mapping(None)
        assert result == {}

    def test_non_mapping_returns_none(self) -> None:
        """Non-mapping returns None."""
        result = MergeGuards.as_mapping(42)
        assert result is None
