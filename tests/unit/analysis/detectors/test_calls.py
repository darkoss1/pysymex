"""Tests for shared detector call helpers."""

from __future__ import annotations

import dis
from typing import cast

from pysymex._internal.analysis.detectors.calls import (
    call_target_candidate_indices,
    extract_argc,
    get_call_target_name,
    is_plausible_callable_name,
    resolve_call_target_name,
)
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.typing.protocols import StackValue


def _instruction(
    *,
    arg: int | None = None,
    argval: object = None,
) -> dis.Instruction:
    def _dummy() -> None:
        return None

    template = next(dis.get_instructions(_dummy))
    return template._replace(opname="CALL", opcode=dis.opmap.get("CALL", 0), arg=arg, argval=argval)


class _NamedCallable:
    def __init__(self, name: str) -> None:
        self.__name__ = name


def _stack(*values: object) -> list[StackValue]:
    return [cast("StackValue", value) for value in values]


def test_extract_argc_prefers_integer_argval() -> None:
    assert extract_argc(_instruction(arg=1, argval=2)) == 2


def test_extract_argc_falls_back_to_integer_arg() -> None:
    assert extract_argc(_instruction(arg=3, argval="not-int")) == 3


def test_call_target_candidate_indices_preserves_candidate_order() -> None:
    assert call_target_candidate_indices(4, 2, prefer_pre_null=True) == (0, 1)
    assert call_target_candidate_indices(4, 2, prefer_pre_null=False) == (1, 0)


def test_resolve_call_target_name_prefers_pre_null_slot_by_default() -> None:
    state = VMState(stack=_stack(_NamedCallable("operator.truediv"), SymbolicNone(), 1, 2))
    assert resolve_call_target_name(state, 2) == "operator.truediv"


def test_resolve_call_target_name_can_prefer_post_null_slot() -> None:
    state = VMState(stack=_stack(_NamedCallable("receiver"), _NamedCallable("receiver.close")))
    assert resolve_call_target_name(state, 0, prefer_pre_null=False) == "receiver.close"


def test_get_call_target_name_ignores_symbolic_none_sentinel() -> None:
    assert get_call_target_name(SymbolicNone()) is None


def test_plausible_callable_filter_rejects_literal_signature_names() -> None:
    candidate = _NamedCallable("('path', 'str', 'mode', 'str')")
    assert is_plausible_callable_name(candidate.__name__) is False
    assert get_call_target_name(candidate, require_plausible_callable=True) is None
