from __future__ import annotations

from pysymex.execution.opcodes.common.functions.classes.descriptors import (
    register_class_body_methods,
)
from pysymex.execution.opcodes.common.functions.classes.init import (
    apply_straight_line_init_assignments,
)
from pysymex.models.objects import SymbolicClass, class_registry


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
