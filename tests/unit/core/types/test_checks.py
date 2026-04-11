import pysymex.core.types.checks
from typing import cast

from pysymex.core.types.scalars import SymbolicValue


class _DummyValue:
    def __init__(self, *, name: str) -> None:
        self._name = name

def test_is_overloaded_arithmetic() -> None:
    """Scenario: operand name carries z3 marker; expected overloaded arithmetic detection."""
    left = cast(SymbolicValue, _DummyValue(name="z3_expr"))
    right = cast(SymbolicValue, _DummyValue(name="plain"))
    assert pysymex.core.types.checks.is_overloaded_arithmetic(left, right) is True


def test_is_type_subscription() -> None:
    """Scenario: global builtin type symbolic name; expected type-subscription detection."""
    container = _DummyValue(name="global_list")
    assert pysymex.core.types.checks.is_type_subscription(container) is True
