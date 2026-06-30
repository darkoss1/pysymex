from __future__ import annotations

from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.registry import class_registry
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.execution.opcodes.common.functions.classes.descriptors.methods import (
    register_class_body_methods,
)
from pysymex._internal.execution.opcodes.common.functions.classes.init import (
    apply_straight_line_init_assignments,
)


def test_straight_line_init_replay_supports_callable_backed_methods() -> None:
    class PlainAccount:
        def __init__(self, balance: int) -> None:
            self.balance = balance

    modeled_cls = SymbolicClass("PlainAccount")
    register_class_body_methods(modeled_cls, PlainAccount)
    instance = class_registry.create_instance(modeled_cls)

    init_method = modeled_cls.get_method("__init__")

    assert init_method is not None
    assert callable(init_method.func)
    assert apply_straight_line_init_assignments(modeled_cls, instance, [7], {})
    assert instance.attrs["balance"] == 7


def test_straight_line_init_replay_preserves_literal_list_as_symbolic_list() -> None:
    class Ledger:
        def __init__(self) -> None:
            self.events: list[object] = []

    modeled_cls = SymbolicClass("Ledger")
    register_class_body_methods(modeled_cls, Ledger)
    instance = class_registry.create_instance(modeled_cls)

    assert apply_straight_line_init_assignments(modeled_cls, instance, [], {})

    events = instance.attrs["events"]
    assert isinstance(events, SymbolicList)
    assert events.concrete_items == []
