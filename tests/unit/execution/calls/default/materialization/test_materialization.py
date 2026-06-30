"""Tests for call default-value and object materialization helpers."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.classes.types import SymbolicMethod
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.execution.calls.default.materialization.attributes import safe_object_attrs
from pysymex._internal.execution.calls.default.materialization.objects import (
    as_named_object_stack_value,
    realize_named_default_objects,
)
from pysymex._internal.execution.calls.default.materialization.values import (
    as_named_default_stack_values,
)


class SafeConcreteReceiver:
    def __init__(self) -> None:
        self.items = [1, 2]
        self.value = 3

    @property
    def boom(self) -> int:
        raise AssertionError("descriptor should not be invoked")

    def method(self) -> int:
        return self.value


def test_repeated_mutable_defaults_preserve_alias_identity() -> None:
    shared_default = [1, 2]

    converted = as_named_default_stack_values({"first": shared_default, "second": shared_default})

    assert converted["first"] is converted["second"]
    assert isinstance(converted["first"], SymbolicList)
    assert converted["first"].name == "first"


def test_safe_object_attrs_reads_dict_without_invoking_descriptors() -> None:
    receiver = SafeConcreteReceiver()

    attrs = safe_object_attrs(receiver)

    assert attrs == {"items": [1, 2], "value": 3}


def test_named_object_stack_value_materializes_attrs_and_methods() -> None:
    receiver = SafeConcreteReceiver()

    materialized = as_named_object_stack_value("receiver", receiver)

    assert materialized is not None
    handle, modeled_attrs = materialized
    assert isinstance(handle, SymbolicObject)
    assert handle.name == "receiver"
    assert isinstance(modeled_attrs["items"], SymbolicList)
    assert modeled_attrs["items"].name == "receiver.items"
    assert isinstance(modeled_attrs["method"], SymbolicMethod)


def test_materialize_named_default_objects_preserves_object_alias_identity() -> None:
    receiver = SafeConcreteReceiver()
    state = VMState()

    state, converted = realize_named_default_objects(
        state,
        {"first": receiver, "second": receiver},
        {},
    )

    assert converted["first"] is converted["second"]
    assert isinstance(converted["first"], SymbolicObject)
    heap_attrs = state.load_heap(converted["first"].address)
    assert isinstance(heap_attrs, dict)
    typed_heap_attrs = cast("dict[object, object]", heap_attrs)
    assert set(typed_heap_attrs) >= {"items", "method", "value"}
