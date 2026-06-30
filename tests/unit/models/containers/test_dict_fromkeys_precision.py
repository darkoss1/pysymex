"""Focused model tests for dict.fromkeys() precision."""

from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.dicts.constructors import DictFromkeysModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_dict_fromkeys_materializes_exact_keys_and_value() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")

    result = DictFromkeysModel().apply([cast(StackValue, [1]), value], {}, _state())

    dictionary = result.value
    assert isinstance(dictionary, SymbolicDict)
    found, retained = dictionary.concrete_value_for_key(1)
    assert found
    assert isinstance(retained, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, retained.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_dict_fromkeys_empty_iterable_materializes_empty_dict() -> None:
    result = DictFromkeysModel().apply([cast(StackValue, [])], {}, _state())

    dictionary = result.value
    assert isinstance(dictionary, SymbolicDict)
    assert dictionary.concrete_items == {}


def test_dict_fromkeys_rejects_non_iterable_argument() -> None:
    result = DictFromkeysModel().apply([SymbolicValue.from_const(1)], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_dict_fromkeys_rejects_exact_unhashable_keys() -> None:
    result = DictFromkeysModel().apply([cast(StackValue, [[1]])], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
