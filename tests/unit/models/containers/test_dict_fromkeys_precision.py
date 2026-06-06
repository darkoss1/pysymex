"""Focused model tests for dict.fromkeys() precision."""

from __future__ import annotations

from typing import cast

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.models.containers.dicts.constructors import DictFromkeysModel
from pysymex.typing import StackValue


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
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_dict_fromkeys_rejects_exact_unhashable_keys() -> None:
    result = DictFromkeysModel().apply([cast(StackValue, [[1]])], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
