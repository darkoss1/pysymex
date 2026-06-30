from __future__ import annotations

import dataclasses
from typing import cast

import pytest
import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.containers.sequence_precision import (
    slice_concrete_backed_sequence,
)
from pysymex._internal.models.builtins.types.containers.tuples.construction import (
    TupleConstructorModel,
)
from pysymex._internal.models.builtins.types.containers.tuples.operations import (
    TupleAddModel,
    TupleHashModel,
    TupleMulModel,
)
from pysymex._internal.models.builtins.types.containers.tuples.queries import (
    TupleContainsModel,
    TupleCountModel,
    TupleGetitemModel,
    TupleIndexModel,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.typing.protocols import StackValue


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
    assert isinstance(TupleConstructorModel().apply([], {}, _state()), ModelResult)
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
    result = TupleConstructorModel().apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_tuple_constructor_copies_heap_backed_symbolic_list_elements() -> None:
    """tuple(heap-backed-list) should preserve elements without aliasing the source."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])
    handle = SymbolicObject("items", 101, z3.IntVal(101), {101})
    vm_state = _state().store_heap(101, source)

    result = TupleConstructorModel().apply([handle], {}, vm_state)

    assert isinstance(result.value, SymbolicList)
    assert result.value is not source
    assert result.value.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_tuple_constructor_materializes_and_consumes_exact_symbolic_iterator() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")
    iterator = SymbolicIterator("items", SymbolicList.from_const([value]))

    result = TupleConstructorModel().apply([iterator], {}, _state())

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


def test_tuple_getitem_symbolic_index_over_exact_items_selects_retained_values() -> None:
    """tuple.__getitem__ should preserve finite index-to-item relationships."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    index = SymbolicValue(
        _name="index",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
    source = dataclasses.replace(SymbolicList.from_const([2, 1]), _type="tuple")

    result = TupleGetitemModel().apply([source, index], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert "potential_exception" not in result.side_effects
    solver = z3.Solver()
    solver.add(branch_constraint, result.value.z3_int == 0)
    assert solver.check() == z3.unsat


def test_tuple_getitem_symbolic_index_over_exact_string_items_selects_strings() -> None:
    """tuple.__getitem__ should preserve finite index-to-string relationships."""
    branch, branch_constraint = SymbolicValue.symbolic_int("tuple_getitem_string_branch")
    index = SymbolicValue.from_z3(branch.z3_int % 2, "tuple_getitem_string_index")
    source = dataclasses.replace(SymbolicList.from_const(["a", "bb"]), _type="tuple")

    result = TupleGetitemModel().apply([source, index], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert "potential_exception" not in result.side_effects
    solver = z3.Solver()
    solver.add(branch_constraint, result.value.z3_len == 0)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int % 2 == 1, result.value.z3_str != "bb")
    assert solver.check() == z3.unsat


def test_tuple_getitem_symbolic_tuple_uses_core_index_bounds_condition() -> None:
    """tuple.__getitem__ fallback keeps CPython index bounds guarded by core semantics."""
    index, index_constraint = SymbolicValue.symbolic_int("tuple_getitem_symbolic_index")
    source = dataclasses.replace(SymbolicList.empty("tuple_source"), _type="tuple")
    source = dataclasses.replace(source, z3_len=z3.IntVal(2))

    result = TupleGetitemModel().apply([source, index], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    condition = effect["condition"]
    solver = z3.Solver()
    solver.add(index_constraint, index.z3_int == -2, condition)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(index_constraint, index.z3_int == -3, z3.Not(condition))
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(index_constraint, index.z3_int == 2, z3.Not(condition))
    assert solver.check() == z3.unsat


def test_tuple_contains_symbolic_value_over_exact_items_preserves_membership() -> None:
    """tuple.__contains__ should prove finite symbolic values are present."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
    source = dataclasses.replace(SymbolicList.from_const([0, 1]), _type="tuple")

    result = TupleContainsModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(branch_constraint, z3.Not(result.value.z3_bool))
    assert solver.check() == z3.unsat


def test_tuple_contains_symbolic_bool_matches_concrete_int_items() -> None:
    """tuple.__contains__ should follow Python bool/int equality."""
    needle, needle_constraint = SymbolicValue.symbolic_bool("needle")
    source = dataclasses.replace(SymbolicList.from_const([0, 1]), _type="tuple")

    result = TupleContainsModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(needle_constraint, z3.Not(result.value.z3_bool))
    assert solver.check() == z3.unsat


def test_tuple_count_symbolic_value_over_exact_items_preserves_positive_count() -> None:
    """tuple.count should prove finite symbolic values are present exactly once."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
    source = dataclasses.replace(SymbolicList.from_const([0, 1]), _type="tuple")

    result = TupleCountModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(branch_constraint, result.value.z3_int != 1)
    assert solver.check() == z3.unsat


def test_tuple_count_symbolic_value_over_exact_items_keeps_zero_count() -> None:
    """tuple.count should keep zero feasible when a finite value is absent."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
    source = dataclasses.replace(SymbolicList.from_const([0]), _type="tuple")

    result = TupleCountModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(branch_constraint, result.value.z3_int == 0)
    assert solver.check() == z3.sat


def test_tuple_index_symbolic_value_over_exact_items_preserves_first_index() -> None:
    """tuple.index should resolve finite symbolic values to their exact first index."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
    source = dataclasses.replace(SymbolicList.from_const([0, 1]), _type="tuple")

    result = TupleIndexModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    missing = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(missing)
    solver = z3.Solver()
    solver.add(branch_constraint, missing["condition"])
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int == 0, result.value.z3_int != 0)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int != 0, result.value.z3_int != 1)
    assert solver.check() == z3.unsat


def test_tuple_index_symbolic_value_over_exact_items_keeps_missing_branch() -> None:
    """tuple.index should keep ValueError feasible when a finite value is absent."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
    source = dataclasses.replace(SymbolicList.from_const([0]), _type="tuple")

    result = TupleIndexModel().apply([source, needle], {}, _state())

    missing = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(missing)
    solver = z3.Solver()
    solver.add(branch_constraint, missing["condition"])
    assert solver.check() == z3.sat


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

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize("model", [TupleCountModel(), TupleIndexModel()])
def test_tuple_public_methods_reject_keywords(model: FunctionModel) -> None:
    """Public tuple methods do not accept keyword parameters."""
    result = model.apply([SymbolicList.empty("tuple_receiver"), 1], {"unexpected": 1}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
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
