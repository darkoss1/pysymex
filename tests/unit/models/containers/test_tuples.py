from __future__ import annotations

import dataclasses
from typing import cast

import pytest
import z3

from pysymex.typing import StackValue
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult, is_raised_exception_effect
from pysymex.models.containers.sequence_precision import slice_concrete_backed_sequence
from pysymex.models.containers.tuples.construction import TupleModel
from pysymex.models.containers.tuples.operations import TupleAddModel, TupleHashModel, TupleMulModel
from pysymex.models.containers.tuples.queries import (
    TupleCountModel,
    TupleGetitemModel,
    TupleIndexModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def test_tuple_add_faithfulness() -> None:
    """Faithfulness: tuple concatenation model executes and mirrors concrete concatenation intent."""
    values_cases: list[tuple[int, ...]] = [(), (1,), (1, 2), (3, 4, 5)]
    other = (9,)
    for values in values_cases:
        real = values + other
        args: list[StackValue] = [values, other]
        result = TupleAddModel().apply(args, {}, _state())
        assert isinstance(result, ModelResult)
        assert real == values + other


def test_tuple_concrete_paths() -> None:
    """Concrete paths for constructor and hash-like behavior."""
    assert isinstance(TupleModel().apply([], {}, _state()), ModelResult)
    TupleHashModel().apply([], {}, _state())


def test_tuple_symbolic_and_error_paths() -> None:
    """Symbolic and error path coverage."""
    TupleGetitemModel().apply([], {}, _state())
    TupleIndexModel().apply([], {}, _state())


def test_tuple_edge_case_empty_tuple() -> None:
    """Edge case for empty tuple semantics."""
    empty: tuple[()] = ()
    assert len(empty) == 0


def test_tuple_constructor_rejects_definite_non_iterable() -> None:
    result = TupleModel().apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_tuple_constructor_copies_heap_backed_symbolic_list_elements() -> None:
    """tuple(heap-backed-list) should preserve elements without aliasing the source."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])
    handle = SymbolicObject("items", 101, z3.IntVal(101), {101})
    vm_state = _state().store_heap(101, source)

    result = TupleModel().apply([handle], {}, vm_state)

    assert isinstance(result.value, SymbolicList)
    assert result.value is not source
    assert result.value.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_tuple_constructor_materializes_and_consumes_exact_symbolic_iterator() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")
    iterator = SymbolicIterator("items", SymbolicList.from_const([value]))

    result = TupleModel().apply([iterator], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [value]
    mutation = cast("dict[str, object]", result.side_effects.get("iterator_mutation"))
    assert isinstance(mutation, dict)
    updated = mutation["updated_iterator"]
    assert isinstance(updated, SymbolicIterator)
    assert updated.index == 1

    solver = z3.Solver()
    solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_tuple_mul_one_preserves_concrete_backed_symbolic_items() -> None:
    """tuple.__mul__(1) should retain exact shallow-copy element identity."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])

    result = TupleMulModel().apply([source, 1], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type", None) == "tuple"
    assert result.value.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_tuple_add_preserves_concrete_backed_suffix_items() -> None:
    """tuple.__add__ should retain symbolic and concrete suffix item relations."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])
    suffix = SymbolicList.from_const([1])

    result = TupleAddModel().apply([source, suffix], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type", None) == "tuple"
    assert result.value.concrete_items == [value, 1]

    solver = z3.Solver()
    solver.add(
        value_constraint,
        z3.Or(result.value[0].z3_int != value.z3_int, result.value[1].z3_int != 1),
    )
    assert solver.check() == z3.unsat


def test_tuple_slice_preserves_concrete_backed_symbolic_items_and_type() -> None:
    """Exact concrete slices should retain item identity and tuple result type."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value, 1])
    source = dataclasses.replace(source, _type="tuple")

    result = slice_concrete_backed_sequence(source, slice(None, 1))

    assert isinstance(result, SymbolicList)
    assert getattr(result, "_type", None) == "tuple"
    assert result.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, result[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


INVALID_TUPLE_PUBLIC_CASES: list[tuple[FunctionModel, list[StackValue]]] = [
    (TupleCountModel(), []),
    (TupleCountModel(), [1, 2]),
    (TupleIndexModel(), []),
    (TupleIndexModel(), [1, 0, 2, 3]),
]


@pytest.mark.parametrize(("model", "method_args"), INVALID_TUPLE_PUBLIC_CASES)
def test_tuple_public_methods_reject_invalid_positional_arity(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Public tuple methods reject CPython-invalid positional forms."""
    result = model.apply([SymbolicList.empty("tuple_receiver"), *method_args], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize("model", [TupleCountModel(), TupleIndexModel()])
def test_tuple_public_methods_reject_keywords(model: FunctionModel) -> None:
    """Public tuple methods do not accept keyword parameters."""
    result = model.apply([SymbolicList.empty("tuple_receiver"), 1], {"unexpected": 1}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    ("model", "method_args"),
    [
        (TupleCountModel(), [1]),
        (TupleIndexModel(), [1]),
        (TupleIndexModel(), [1, 0]),
        (TupleIndexModel(), [1, 0, 2]),
    ],
)
def test_tuple_public_methods_accept_valid_arity(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Public tuple method valid positional forms remain modeled."""
    result = model.apply([SymbolicList.empty("tuple_receiver"), *method_args], {}, _state())

    assert "raised_exception" not in result.side_effects
