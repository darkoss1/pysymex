from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.predicates.evaluator import filter_item_truth
from pysymex._internal.models.builtins.iteration.lazy import FilterModel, MapModel
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (MapModel(), [str, 1]),
        (MapModel(), [str, [1], SymbolicValue.from_const(1)]),
        (FilterModel(), [None, 1]),
        (FilterModel(), [None, SymbolicValue.from_const(1)]),
    ],
)
def test_lazy_iterator_constructors_reject_definite_non_iterables(
    model: FunctionModel, args: list[StackValue]
) -> None:
    result = model.apply(args, {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_filter_predicate_materializes_modeled_bytearray_payload() -> None:
    def keep_bytearray_b(value: object) -> bool:
        return value == b"b"

    payload = SymbolicList.from_const([ord("b")])
    payload.set_runtime_type("bytearray")
    item = SymbolicValue.from_const(0)
    item.attach_modeled_object(payload)

    truth = filter_item_truth(keep_bytearray_b, item)

    assert truth is not None
    assert z3.is_true(z3.simplify(truth))
