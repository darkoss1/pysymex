from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.instances import SymbolicInstance
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.functions.classes.instances.values import (
    modeled_instance_value,
)
from pysymex._internal.models.builtins.iteration.aggregates import SortedModel
from pysymex._internal.typing.protocols import StackValue
from tests.unit.models.builtins.core_model_helpers import state


def _item_lt(self: object, other: object) -> bool:
    return self.value < other.value  # type: ignore[attr-defined]


def _descending_item_lt(self: object, other: object) -> bool:
    return self.value > other.value  # type: ignore[attr-defined]


def _constant_lt(self: object, other: object) -> bool:
    _ = self, other
    return True


def _modeled_item_values(method_code: object) -> list[StackValue]:
    cls = SymbolicClass("Item")
    cls.add_method("__lt__", method_code, parameters=["self", "other"])
    first = SymbolicInstance(cls, 1, attrs={"value": SymbolicValue.from_const(2)})
    second = SymbolicInstance(cls, 2, attrs={"value": SymbolicValue.from_const(1)})
    return [
        modeled_instance_value("Item", first, 1),
        modeled_instance_value("Item", second, 2),
    ]


def _item_attr_values(items: list[object]) -> list[object]:
    values: list[object] = []
    for item in items:
        assert isinstance(item, SymbolicValue)
        instance = getattr(item, "_modeled_object", None)
        assert isinstance(instance, SymbolicInstance)
        attr = instance.attrs["value"]
        assert isinstance(attr, SymbolicValue)
        values.append(attr.value)
    return values


def test_sorted_model_sorts_modeled_instances_by_exact_lt_attribute() -> None:
    result = SortedModel().apply([_modeled_item_values(_item_lt.__code__)], {}, state())

    assert isinstance(result.value, SymbolicList)
    concrete_items = result.value.concrete_items
    assert concrete_items is not None
    assert _item_attr_values(concrete_items) == [1, 2]
    assert z3.is_true(simplify_expr(result.value.z3_len == 2))


def test_sorted_model_respects_reverse_for_exact_lt_attribute() -> None:
    kwargs: dict[str, StackValue] = {"reverse": True}
    result = SortedModel().apply([_modeled_item_values(_item_lt.__code__)], kwargs, state())

    assert isinstance(result.value, SymbolicList)
    concrete_items = result.value.concrete_items
    assert concrete_items is not None
    assert _item_attr_values(concrete_items) == [2, 1]


def test_sorted_model_handles_descending_exact_lt_attribute() -> None:
    result = SortedModel().apply([_modeled_item_values(_descending_item_lt.__code__)], {}, state())

    assert isinstance(result.value, SymbolicList)
    concrete_items = result.value.concrete_items
    assert concrete_items is not None
    assert _item_attr_values(concrete_items) == [2, 1]


def test_sorted_model_does_not_sort_unrecognized_modeled_lt() -> None:
    result = SortedModel().apply([_modeled_item_values(_constant_lt.__code__)], {}, state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items is None
    assert cast("list[object]", result.constraints)
