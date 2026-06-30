from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.conversions.boolean import BoolModel
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    ("receiver", "expected"),
    [
        (SymbolicString.from_const(""), False),
        (SymbolicString.from_const("value"), True),
        (SymbolicList.from_const([]), False),
        (SymbolicList.from_const([1]), True),
        (SymbolicDict.from_const({}), False),
        (SymbolicDict.from_const({"value": 1}), True),
        (SymbolicValue.from_const(0), False),
        (SymbolicValue.from_const(1), True),
        (SymbolicValue.from_const(""), False),
    ],
)
def test_bool_preserves_known_carrier_truth(receiver: StackValue, expected: bool) -> None:
    assert BoolModel().apply([receiver], {}, _state()).value is expected


def test_bool_symbolic_list_result_tracks_symbolic_length() -> None:
    receiver, receiver_constraint = SymbolicList.symbolic("receiver")
    result = BoolModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(receiver_constraint, *result.constraints, receiver.z3_len == 0)
    solver.add(result.value.z3_bool)
    assert solver.check() == z3.unsat


def test_bool_resolves_heap_backed_list_handle() -> None:
    storage = SymbolicList.from_const([1])
    handle = SymbolicObject("events_handle", 10, z3.IntVal(10), {10})
    state = VMState(memory={10: storage}, pc=0)

    result = BoolModel().apply([handle], {}, state)

    assert result.value is True
