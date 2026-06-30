from __future__ import annotations

import dis
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.collections.mutation.dicts import (
    handle_common_dict_merge_update,
)
from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True)
class Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


def _instr(
    opname: str, argval: object = None, arg: int | None = None, offset: int = 0
) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, arg=arg, offset=offset)


def _kwargs_target(**kwargs: object) -> dict[str, object]:
    return kwargs


def _dict_merge_state(
    function: Callable[..., object], value: StackValue
) -> tuple[VMState, OpcodeDispatcher]:
    stack = cast("list[StackValue]", [function, None, (), SymbolicDict.from_const({}), value])
    return VMState(stack=stack, pc=0), OpcodeDispatcher()


def test_dict_merge_reports_symbolic_int_kwargs_type_error() -> None:
    kwargs_val, type_constraint = SymbolicValue.symbolic_int("kwargs")
    state, dispatcher = _dict_merge_state(_kwargs_target, kwargs_val)
    state = state.add_constraint(type_constraint)

    result = handle_common_dict_merge_update(
        _instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        dispatcher,
    )

    assert result.terminal is True
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "argument after ** must be a mapping, not int" in result.issues[0].message


def test_dict_merge_routes_symbolic_int_kwargs_type_error() -> None:
    dispatcher = OpcodeDispatcher()
    merge = _instr("DICT_MERGE", 1, arg=1, offset=4)
    dispatcher.set_instructions([merge, _instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    kwargs_val, type_constraint = SymbolicValue.symbolic_int("kwargs")
    state, _ = _dict_merge_state(_kwargs_target, kwargs_val)
    state = state.add_constraint(type_constraint)

    result = handle_common_dict_merge_update(merge, state, dispatcher)

    assert result.terminal is False
    assert result.issues == []
    routed = result.new_states[0].stack[-1]
    assert isinstance(routed, SymbolicException)
    assert routed.type_name == "TypeError"
    assert "argument after ** must be a mapping, not int" in str(routed)


def test_dict_merge_keeps_unknown_symbolic_kwargs_unreported() -> None:
    kwargs_val, type_constraint = SymbolicValue.symbolic("maybe_kwargs")
    state, dispatcher = _dict_merge_state(_kwargs_target, kwargs_val)
    state = state.add_constraint(type_constraint)

    result = handle_common_dict_merge_update(
        _instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        dispatcher,
    )

    assert result.terminal is False
    assert result.issues == []
    assert len(result.new_states) == 1
