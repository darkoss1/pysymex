from __future__ import annotations

import pytest
import z3

from pysymex._internal.analysis.runtime.summaries.builder import SummaryBuilder
from pysymex._internal.core.memory.cow.dicts import CowDict
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import CallFrame, VMStateError, copy_summary_builder


class _UncopyableBuilder:
    def __copy__(self) -> _UncopyableBuilder:
        raise TypeError("copy failed")


class _BrokenCloneBuilder:
    def clone(self) -> object:
        raise TypeError("clone failed")


def test_copy_summary_builder_uses_summary_builder_clone() -> None:
    original = SummaryBuilder("f").add_parameter("x", "int").require(z3.BoolVal(True))

    copied = copy_summary_builder(original)

    assert isinstance(copied, SummaryBuilder)
    copied.add_parameter("y", "int").ensure(z3.BoolVal(False))
    assert [param.name for param in original.build().parameters] == ["x"]
    assert [param.name for param in copied.build().parameters] == ["x", "y"]
    assert len(original.build().postconditions) == 0
    assert len(copied.build().postconditions) == 1


def test_copy_summary_builder_requires_clone() -> None:
    with pytest.raises(VMStateError, match="must define clone"):
        copy_summary_builder(_UncopyableBuilder())


def test_copy_summary_builder_raises_when_clone_fails() -> None:
    with pytest.raises(VMStateError, match="Failed to clone call-frame summary builder"):
        copy_summary_builder(_BrokenCloneBuilder())


def test_vm_state_fork_does_not_share_call_frame_summary_builder() -> None:
    builder = SummaryBuilder("callee").add_parameter("x", "int")
    state = VMState(
        call_stack=[
            CallFrame(
                function_name="callee",
                return_pc=3,
                local_vars=CowDict({"x": 1}),
                stack_depth=0,
                summary_builder=builder,
            )
        ]
    )

    forked = state.fork()
    original_builder = state.call_stack[0].summary_builder
    forked_builder = forked.call_stack[0].summary_builder

    assert isinstance(original_builder, SummaryBuilder)
    assert isinstance(forked_builder, SummaryBuilder)
    assert forked_builder is not original_builder

    forked_builder.add_parameter("branch_only", "int")

    assert [param.name for param in original_builder.build().parameters] == ["x"]
    assert [param.name for param in forked_builder.build().parameters] == [
        "x",
        "branch_only",
    ]


def test_fork_call_stack_reuses_frames_when_no_summary_builders_are_active() -> None:
    frame = CallFrame("callee", 3, CowDict({"x": 1}), 0)
    call_stack = [frame]

    forked = CallFrame.fork_stack(call_stack)

    assert forked == [frame]
    assert forked is not call_stack
    assert forked[0] is frame


def test_fork_call_stack_cow_forks_locals_when_summary_builder_is_active() -> None:
    builder = SummaryBuilder("callee")
    frame = CallFrame(
        function_name="callee",
        return_pc=3,
        local_vars=CowDict({"x": 1}),
        stack_depth=0,
        summary_builder=builder,
    )

    forked = CallFrame.fork_stack([frame])

    assert forked[0] is not frame
    assert forked[0].local_vars is not frame.local_vars

    forked[0].local_vars["x"] = 2
    forked[0].local_vars["branch_only"] = 3

    assert frame.local_vars["x"] == 1
    assert "branch_only" not in frame.local_vars
