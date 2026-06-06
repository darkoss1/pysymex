from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.detectors import DeferredDetectorIssue
from pysymex.execution.strategies.merger.factory import create_state_merger
from pysymex.execution.strategies.merger.state import StateMerger
from pysymex.execution.strategies.merger.types import (
    AbstractVarInfo,
    MergePolicy,
    MergeStatistics,
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

    def test_detect_join_points(self) -> None:
        """Test detect_join_points behavior."""
        code = compile("x = 0\nif x:\n    y = 1\nelse:\n    y = 2\n", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        merger = StateMerger()
        join_points = merger.detect_join_points(instructions)
        assert isinstance(join_points, set)

    def test_detect_join_points_excludes_backward_jump_targets(self) -> None:
        """Loop headers are handled by loop logic, not ordinary state merging."""

        def target() -> int:
            total = 0
            step = 0
            while step < 3:
                total += step
                step += 1
            return total

        instructions = list(dis.get_instructions(target))
        offset_to_index = {instr.offset: idx for idx, instr in enumerate(instructions)}
        backward_targets = {
            offset_to_index[instr.argval]
            for idx, instr in enumerate(instructions)
            if (instr.opcode in dis.hasjabs or instr.opcode in dis.hasjrel)
            and isinstance(instr.argval, int)
            and instr.argval in offset_to_index
            and offset_to_index[instr.argval] <= idx
        }

        merger = StateMerger()
        join_points = merger.detect_join_points(instructions)

        assert backward_targets
        assert join_points.isdisjoint(backward_targets)

    def test_is_join_point(self) -> None:
        """Test is_join_point behavior."""
        merger = StateMerger()
        merger.join_points = {5}
        assert merger.is_join_point(5) is True
        assert merger.is_join_point(1) is False

    def test_should_merge(self) -> None:
        """Test should_merge behavior."""
        merger = StateMerger(max_constraints_for_merge=2)
        merger.join_points = {7}
        state = VMState(pc=7, path_constraints=[z3.Bool("a")])
        assert merger.should_merge(state) is True

    def test_pending_detector_issue_prevents_merge_and_changes_state_identity(self) -> None:
        merger = StateMerger()
        merger.join_points = {7}
        deferred = DeferredDetectorIssue(
            Issue(kind=IssueKind.DIVISION_BY_ZERO, message="deferred", pc=3),
            (1, 3, IssueKind.DIVISION_BY_ZERO),
        )
        pending = VMState(pc=7, deferred_detector_issues=[deferred])
        ordinary = VMState(pc=7)

        assert merger.should_merge(pending) is False
        assert pending.hash_value() != ordinary.hash_value()

    def test_retained_caller_stack_changes_suspended_state_identity(self) -> None:
        from pysymex.core.state.types import CallFrame, wrap_cow_dict

        first = VMState(
            pc=7,
            call_stack=[
                CallFrame("callee", 2, wrap_cow_dict({}), 1, (SymbolicValue.from_const(1),))
            ],
        )
        second = VMState(
            pc=7,
            call_stack=[
                CallFrame("callee", 2, wrap_cow_dict({}), 1, (SymbolicValue.from_const(2),))
            ],
        )

        assert first.hash_value() != second.hash_value()

    def test_add_state_for_merge(self) -> None:
        """Test add_state_for_merge behavior."""
        merger = StateMerger()
        state = VMState(pc=1)
        added = merger.add_state_for_merge(state)
        assert added is state
        assert merger.stats.states_before_merge == 1

    def test_reset(self) -> None:
        """Test reset behavior."""
        merger = StateMerger()
        merger.add_state_for_merge(VMState(pc=9))
        merger.reset()
        assert merger.pending_states == {}
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
        from pysymex.core.types.scalars.values import SymbolicValue

        val = SymbolicValue.from_const(42)
        from pysymex.execution.strategies.merger.helpers import is_any_symbolic

        assert is_any_symbolic(val) is True

    def test_is_any_symbolic_with_non_symbolic(self) -> None:
        """Test that _is_any_symbolic returns False for non-symbolic types."""
        from pysymex.execution.strategies.merger.helpers import is_any_symbolic

        assert is_any_symbolic(42) is False
        assert is_any_symbolic("string") is False
        assert is_any_symbolic(None) is False

    def test_is_conditional_mergeable_with_callable(self) -> None:
        """Test that _is_conditional_mergeable returns True for callable conditional_merge."""
        from pysymex.core.types.scalars.values import SymbolicValue

        val = SymbolicValue.from_const(42)
        from pysymex.execution.strategies.merger.helpers import is_conditional_mergeable

        assert is_conditional_mergeable(val) is True

    def test_is_conditional_mergeable_without_callable(self) -> None:
        """Test that _is_conditional_mergeable returns False for non-callable."""
        from pysymex.execution.strategies.merger.helpers import is_conditional_mergeable

        assert is_conditional_mergeable(42) is False
        assert is_conditional_mergeable("string") is False

    def test_is_stack_value_with_valid_types(self) -> None:
        """Test that _is_stack_value returns True for valid stack value types."""
        from pysymex.execution.strategies.merger.helpers import is_stack_value

        assert is_stack_value(None) is True
        assert is_stack_value(42) is True
        assert is_stack_value(True) is True
        assert is_stack_value("string") is True
        assert is_stack_value(3.14) is True
        assert is_stack_value(b"bytes") is True
        assert is_stack_value(int) is True
        assert is_stack_value([1, 2, 3]) is True
        assert is_stack_value((1, 2, 3)) is True
        assert is_stack_value({"key": "value"}) is True
        assert is_stack_value(lambda: None) is True

    def test_is_stack_value_with_invalid_types(self) -> None:
        """Test that _is_stack_value returns False for invalid stack value types."""
        from pysymex.execution.strategies.merger.helpers import is_stack_value

        class CustomClass:
            pass

        assert is_stack_value(CustomClass()) is False

    def test_as_string_object_mapping_with_mapping(self) -> None:
        """Test that _as_string_object_mapping converts valid mapping to dict."""
        from pysymex.execution.strategies.merger.helpers import as_string_object_mapping

        mapping: dict[str, int] = {"key": 42}
        result = as_string_object_mapping(mapping)
        assert result is not None
        assert result == {"key": 42}

    def test_as_string_object_mapping_with_none(self) -> None:
        """Test that _as_string_object_mapping returns empty dict for None."""
        from pysymex.execution.strategies.merger.helpers import as_string_object_mapping

        result = as_string_object_mapping(None)
        assert result is not None
        assert result == {}
