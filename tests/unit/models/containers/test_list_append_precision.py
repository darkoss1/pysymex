from __future__ import annotations

import dataclasses
from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.lists.mutations.growth import (
    ListAppendModel,
)


def test_list_append_retains_tuple_shaped_symbolic_item() -> None:
    """list.append should retain exact tuple containers for later iteration/unpack."""
    value, _constraint = SymbolicValue.symbolic_int("value")
    tuple_item = dataclasses.replace(SymbolicList.from_const([0, value]), _type="tuple")
    source = SymbolicList.from_const([])

    result = ListAppendModel().apply([source, tuple_item], {}, VMState(pc=0))

    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    retained_items = updated.concrete_items
    assert retained_items == [tuple_item]
    assert retained_items is not None
    assert retained_items[0] is tuple_item
