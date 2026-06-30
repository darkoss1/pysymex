from __future__ import annotations

import z3

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.sequence_precision import (
    concrete_bool_value,
    insert_retained_sequence_item,
    normalize_concrete_index,
    normalize_insert_index,
    remove_first_retained_sequence_item,
    reverse_retained_sequence,
    retained_sequence_absence_condition,
    sequence_index_error_condition,
    sequence_index_value,
    sort_retained_sequence,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue


def test_retained_sequence_absence_condition_models_bool_int_equality() -> None:
    needle, needle_constraint = SymbolicValue.symbolic_bool("sequence_absence_bool")

    absence = retained_sequence_absence_condition([0, 1], needle)

    assert absence is not None
    solver = z3.Solver()
    solver.add(needle_constraint, absence)
    assert solver.check() == z3.unsat


def test_retained_sequence_absence_condition_requires_supported_items() -> None:
    needle, _ = SymbolicValue.symbolic_int("sequence_absence_unsupported")

    assert retained_sequence_absence_condition([object()], needle) is None


def test_remove_first_retained_sequence_item_uses_python_bool_int_equality() -> None:
    source = SymbolicList.from_const([False, 0, 1])

    updated = remove_first_retained_sequence_item(source, 0)

    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [0, 1]


def test_remove_first_retained_sequence_item_preserves_symbolic_suffix() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("sequence_remove_suffix")
    source = SymbolicList.from_const([1, value])

    updated = remove_first_retained_sequence_item(source, 1)

    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [value]
    solver = z3.Solver()
    solver.add(value_constraint, updated[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_normalize_insert_index_matches_cpython_bounds_behavior() -> None:
    assert normalize_insert_index(-10, 3) == 0
    assert normalize_insert_index(-1, 3) == 2
    assert normalize_insert_index(10, 3) == 3
    assert normalize_insert_index(True, 3) == 1


def test_normalize_concrete_index_matches_cpython_existing_index_behavior() -> None:
    assert normalize_concrete_index(-3, 3) == 0
    assert normalize_concrete_index(-1, 3) == 2
    assert normalize_concrete_index(2, 3) == 2
    assert normalize_concrete_index(-4, 3) is None
    assert normalize_concrete_index(3, 3) is None


def test_insert_retained_sequence_item_preserves_symbolic_item_relationships() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("sequence_insert_item")
    source = SymbolicList.from_const([1, 3])

    updated = insert_retained_sequence_item(source, 1, value)

    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [1, value, 3]
    solver = z3.Solver()
    solver.add(value_constraint, updated[1].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_insert_retained_sequence_item_uses_cpython_negative_index_clamping() -> None:
    source = SymbolicList.from_const([1, 2])

    updated = insert_retained_sequence_item(source, -10, 0)

    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [0, 1, 2]


def test_reverse_retained_sequence_preserves_symbolic_items() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("sequence_reverse_item")
    source = SymbolicList.from_const([1, value])

    updated = reverse_retained_sequence(source)

    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [value, 1]
    solver = z3.Solver()
    solver.add(value_constraint, updated[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_sort_retained_sequence_uses_cpython_ordering_and_reverse_flag() -> None:
    source = SymbolicList.from_const([2, 1, 3])

    updated = sort_retained_sequence(source, reverse=True)

    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [3, 2, 1]


def test_sort_retained_sequence_returns_none_for_unsupported_ordering() -> None:
    source = SymbolicList.from_const([object(), object()])

    assert sort_retained_sequence(source) is None


def test_concrete_bool_value_reads_symbolic_bool_constants() -> None:
    true_value = SymbolicValue.from_const(True)
    false_value = SymbolicValue.from_const(False)

    assert concrete_bool_value(true_value) is True
    assert concrete_bool_value(false_value) is False


def test_sequence_index_value_accepts_cpython_int_like_indexes() -> None:
    bool_index = sequence_index_value(True)
    int_index = sequence_index_value(-1)
    symbolic_index, _ = SymbolicValue.symbolic_int("sequence_symbolic_index")

    assert isinstance(bool_index, SymbolicValue)
    assert bool_index.value == 1
    assert isinstance(int_index, SymbolicValue)
    assert int_index.value == -1
    assert sequence_index_value(symbolic_index) is symbolic_index
    assert sequence_index_value("0") is None


def test_sequence_index_error_condition_matches_cpython_bounds() -> None:
    source = SymbolicList.from_const([1, 2])

    valid = sequence_index_error_condition(source, SymbolicValue.from_const(-2))
    too_negative = sequence_index_error_condition(source, SymbolicValue.from_const(-3))
    too_large = sequence_index_error_condition(source, SymbolicValue.from_const(2))

    assert z3.is_false(z3.simplify(valid))
    assert z3.is_true(z3.simplify(too_negative))
    assert z3.is_true(z3.simplify(too_large))
