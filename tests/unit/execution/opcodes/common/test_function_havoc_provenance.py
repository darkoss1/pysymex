from __future__ import annotations

import dis

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.fallback.types import FallbackKind, RiskLevel, SoundnessTag
from pysymex._internal.execution.opcodes.common.functions.call import handle_common_call
from pysymex._internal.execution.opcodes.common.functions.call_ex import (
    handle_common_call_function_ex,
)


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def _instr_with_arg(opname: str, arg: int) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, arg=arg, argval=arg)


def _assert_object_str_havoc(result: OpcodeResult, pc: int) -> None:
    assert result.terminal is False
    assert result.degraded_passes == ["unmodeled_call_abstraction"]
    assert len(result.fallback_events) == 1

    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == "unmodeled_call_abstraction"
    assert event.owner == "execution.calls"
    assert event.reason == "unmodeled call target 'object.__str__' abstracted with havoc"
    assert event.pc == pc
    assert event.soundness is SoundnessTag.PRECISION_LOSS
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH

    next_state = result.new_states[0]
    assert next_state.pc == pc + 1
    assert len(next_state.path_constraints) == 1

    top = next_state.stack[-1]
    assert isinstance(top, HavocValue)
    assert top.name.startswith("havoc_call_")
    assert top.name.endswith(f"@{pc}")
    assert "object" in top.name
    assert "str" in top.name


def test_unmodeled_call_havoc_name_preserves_callable_provenance() -> None:
    pc = 12
    state = VMState(stack=[SymbolicNone(), object.__str__], pc=pc)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    _assert_object_str_havoc(result, pc)


def test_unmodeled_call_function_ex_havoc_name_preserves_callable_provenance() -> None:
    pc = 13
    state = VMState(stack=[object.__str__, SymbolicNone("PUSH_NULL_None"), ()], pc=pc)

    result = handle_common_call_function_ex(
        _instr_with_arg("CALL_FUNCTION_EX", 0), state, OpcodeDispatcher()
    )

    _assert_object_str_havoc(result, pc)
