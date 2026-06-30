from __future__ import annotations

import dis
from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.calls.interprocedural.activation import activate_callee_bytecode
from pysymex._internal.execution.calls.interprocedural.bytecode import load_callee_bytecode
from pysymex._internal.execution.calls.interprocedural.partials import expand_partial_call
from pysymex._internal.execution.calls.interprocedural.signature import callee_signature
from pysymex._internal.execution.calls.interprocedural.summaries import (
    build_interprocedural_summary,
)
from pysymex._internal.execution.calls.interprocedural.targets import InterproceduralTarget
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.models.stdlib.functools.core import PartialModel


def test_load_callee_bytecode_returns_instruction_stream() -> None:
    def sample(value: int) -> int:
        return value + 1

    loaded = load_callee_bytecode(sample.__code__)

    assert loaded is not None
    assert all(isinstance(instruction, dis.Instruction) for instruction in loaded.instructions)
    assert any(instruction.opname == "RETURN_VALUE" for instruction in loaded.instructions)


def test_callee_signature_slices_positional_and_keyword_only_names() -> None:
    def sample(left: int, right: int = 0, *, scale: int = 1) -> int:
        return (left + right) * scale

    signature = callee_signature(sample.__code__)

    assert signature.arg_count == 2
    assert signature.pos_arg_names == ("left", "right")
    assert signature.kwonly_arg_names == ("scale",)


def test_activate_callee_bytecode_sets_callee_stream_and_depth() -> None:
    def sample() -> int:
        return 1

    dispatcher = OpcodeDispatcher()
    instructions = list(dis.get_instructions(sample.__code__))
    state = VMState(pc=9, depth=3)

    activated = activate_callee_bytecode(
        state=state,
        ctx=dispatcher,
        new_locals={"x": 1},
        callee_instructions=instructions,
        exception_entries=[],
    )

    assert activated.pc == 0
    assert activated.depth == 4
    assert activated.local_vars["x"] == 1
    assert activated.current_instructions == list(instructions)
    assert dispatcher.instructions == instructions


def test_expand_partial_call_merges_bound_and_call_site_arguments() -> None:
    def sample(left: int, right: int, *, scale: int = 1) -> int:
        return (left + right) * scale

    partial = PartialModel(sample, 2, scale=3)

    expanded = expand_partial_call(partial, [5], {"scale": 4})

    assert expanded is not None
    assert expanded.func_obj is sample
    assert expanded.args == [2, 5]
    assert expanded.kwargs == {"scale": 4}


def test_build_interprocedural_summary_records_target_parameters() -> None:
    def sample(value: int, *, scale: int = 1) -> int:
        return value * scale

    target = InterproceduralTarget(
        func_obj=sample,
        func_code=sample.__code__,
        func_name="sample",
        symbolic_closure=(),
        args=[7],
        kwargs={},
    )
    dispatcher = cast("OpcodeDispatcher", _SummaryEnabledDispatcher())

    builder = build_interprocedural_summary(dispatcher, target, ("value",), ("scale",))

    assert builder is not None
    summary = builder.build()
    assert builder.initial_args == [7]
    assert summary.qualname == "sample"
    assert [parameter.name for parameter in summary.parameters] == ["value", "scale"]


class _SummaryEnabledCrossFunction:
    function_summary_cache: dict[str, object] = {}


class _SummaryEnabledDispatcher:
    cross_function = _SummaryEnabledCrossFunction()
