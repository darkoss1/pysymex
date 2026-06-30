from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.functions.classes.instances.aliases import (
    replace_identity_references,
)
from pysymex._internal.typing.protocols import StackValue


def test_replace_identity_references_rewrites_retained_symbolic_list_items() -> None:
    old = SymbolicValue.from_const("old")
    new = SymbolicValue.from_const("new")
    retained = SymbolicList.from_const([old])
    state = VMState(stack=[retained], pc=0)

    replace_identity_references(state, old, new)

    updated = state.stack[0]
    assert isinstance(updated, SymbolicList)
    assert updated is not retained
    assert updated.concrete_items == [new]


def test_replace_identity_references_rewrites_nested_tuple_retained_items() -> None:
    old = SymbolicValue.from_const("old")
    new = SymbolicValue.from_const("new")
    retained = SymbolicList.from_const([old])
    state = VMState(stack=[(retained,)], pc=0)

    replace_identity_references(state, old, new)

    updated_tuple = state.stack[0]
    assert isinstance(updated_tuple, tuple)
    updated = cast("StackValue", updated_tuple[0])
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [new]
