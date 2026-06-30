"""Focused model tests for dictionary view item precision."""

from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dict_views import SymbolicDictView
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.dicts.views import (
    DictItemsModel,
    DictKeysModel,
    DictValuesModel,
)
from pysymex._internal.models.contracts.results import ModelResult


def _state() -> VMState:
    return VMState(pc=0)


def test_dict_items_preserves_retained_key_value_pair() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"k": value})

    result = DictItemsModel().apply([source], {}, _state())

    assert isinstance(result, ModelResult)
    items = result.value
    assert isinstance(items, SymbolicDictView)
    retained_items = items.concrete_items
    assert isinstance(retained_items, list)
    assert len(retained_items) == 1
    key, retained_value = cast("tuple[str, SymbolicValue]", retained_items[0])
    assert key == "k"

    solver = z3.Solver()
    solver.add(value_constraint, retained_value.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_empty_dict_views_materialize_as_empty_lists() -> None:
    source = SymbolicDict.from_const({})

    keys = DictKeysModel().apply([source], {}, _state()).value
    values = DictValuesModel().apply([source], {}, _state()).value
    items = DictItemsModel().apply([source], {}, _state()).value

    assert isinstance(keys, SymbolicDictView)
    assert isinstance(values, SymbolicDictView)
    assert isinstance(items, SymbolicDictView)
    assert keys.concrete_items == []
    assert values.concrete_items == []
    assert items.concrete_items == []
