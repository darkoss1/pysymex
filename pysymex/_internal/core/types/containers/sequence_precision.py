# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Core retained-item precision helpers for finite sequence semantics."""

from __future__ import annotations

import dataclasses
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType, fresh_name
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps
from pysymex._internal.core.solver.feasibility_context import path_may_be_feasible

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

# Small repeats keep concrete metadata; larger repeats use an exact lazy array view.
_EAGER_REPEAT_MATERIALIZATION_THRESHOLD = 32
PATH_SUFFIXES_SEQUENCE_KIND = "path.suffixes"
_MISSING_INDEX_BOUND = object()


@dataclasses.dataclass(frozen=True)
class RetainedSequenceIndexResult:
    """Exact ``sequence.index`` result over retained items."""

    value: SymbolicValue
    found_condition: z3.BoolRef


@dataclasses.dataclass(frozen=True)
class RetainedSequenceItemResult:
    """Exact item selected from a retained finite sequence."""

    value: StackValue
    item_condition: z3.BoolRef


def concat_concrete_backed_sequences(
    left: SymbolicList,
    right: SymbolicList,
) -> SymbolicList | None:
    """Return an exact retained-item concatenation when both inputs are fully known."""
    left_items = exact_concrete_items(left)
    right_items = exact_concrete_items(right)
    if left_items is None or right_items is None:
        return None
    return SymbolicList.from_const([*left_items, *right_items])


def repeat_concrete_backed_sequence(value: SymbolicList, count: int) -> SymbolicList | None:
    """Return an exact eager or lazy repetition for a concrete repeat count."""
    items = exact_concrete_items(value)
    if items is None:
        return None
    if count <= 0:
        return SymbolicList.from_const([])
    if not items:
        return SymbolicList.from_const([])
    repeated_length = len(items) * count
    if repeated_length <= _EAGER_REPEAT_MATERIALIZATION_THRESHOLD:
        return SymbolicList.from_const(items * count)

    index = z3.Int(fresh_name(f"{value.name}_repeat_idx"))
    repeated_array = cast(
        "z3.ArrayRef",
        z3.Lambda(
            [index],
            z3.Select(value.z3_array, index % len(items)),
        ),
    )
    return SymbolicList(
        _name=f"{value.name}*{count}",
        z3_array=repeated_array,
        z3_len=ConstraintValues.int(repeated_length),
        element_type=value.element_type,
    )


def slice_concrete_backed_sequence(
    value: SymbolicList,
    key: slice,
    constraints: list[z3.BoolRef] | None = None,
) -> SymbolicList | None:
    """Return an exact retained-item slice when the input sequence is fully known."""
    items = exact_concrete_items(value, constraints)
    if items is None:
        return None
    result = SymbolicList.from_const(items[key])
    sequence_type = getattr(value, "_type", None) or "list"
    return dataclasses.replace(result, _type=sequence_type)


def exact_concrete_items(
    value: SymbolicList,
    constraints: list[z3.BoolRef] | None = None,
) -> list[object] | None:
    """Return retained items only when they describe the full concrete sequence length."""
    items = value.concrete_items
    if items is None:
        return derived_concrete_items(value, constraints)
    length = simplify_expr(value.z3_len)
    if not z3.is_int_value(length) or length.as_long() != len(items):
        return None
    return items


def retained_sequence_contains_value(
    value: SymbolicList,
    needle: object,
    constraints: list[z3.BoolRef] | None = None,
) -> SymbolicValue | bool | None:
    """Return exact membership over retained sequence items when possible."""
    items = exact_concrete_items(value, constraints)
    if items is None:
        return None
    if not items:
        return False
    if not isinstance(needle, SymbolicValue | SymbolicString):
        return needle in items

    conditions = [
        condition
        for item in items
        if (condition := retained_item_equality_condition(needle, item)) is not None
    ]
    if not conditions:
        return None
    return _bool_value(
        f"{getattr(needle, 'name', needle)!s} in {getattr(value, 'name', 'sequence')}",
        z3.Or(*conditions),
    )


def retained_sequence_count_value(
    value: SymbolicList,
    needle: object,
    constraints: list[z3.BoolRef] | None = None,
) -> SymbolicValue | int | None:
    """Return exact ``sequence.count(needle)`` over retained items when possible."""
    items = exact_concrete_items(value, constraints)
    if items is None:
        return None
    if not items:
        return 0

    needle_value = _sequence_needle_value(needle)
    if needle_value is None:
        if any(isinstance(item, SymbolicValue | SymbolicString) for item in items):
            return None
        return items.count(needle)

    conditions: list[z3.BoolRef] = []
    for item in items:
        condition = retained_item_equality_condition(needle_value, item)
        if condition is None:
            return None
        conditions.append(condition)

    count_expr = simplify_expr(
        sum((z3.If(condition, Z3_ONE, Z3_ZERO) for condition in conditions), Z3_ZERO),
    )
    return SymbolicValue(
        _name=f"{getattr(value, 'name', 'sequence')}.count({getattr(needle, 'name', needle)!s})",
        z3_int=count_expr,
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )


def retained_sequence_absence_condition(
    items: list[object] | None,
    needle: object,
) -> z3.BoolRef | None:
    """Return an exact non-membership predicate for retained sequence items."""
    if items is None:
        return None
    if not items:
        return Z3_TRUE

    needle_value = _sequence_needle_value(needle)
    if needle_value is None:
        try:
            return Z3_TRUE if needle not in items else Z3_FALSE
        except TypeError:
            return None

    equality_conditions: list[z3.BoolRef] = []
    for item in items:
        condition = retained_item_equality_condition(needle_value, item)
        if condition is None:
            return None
        equality_conditions.append(condition)
    return simplify_expr(z3.Not(z3.Or(*equality_conditions)))


def remove_first_retained_sequence_item(
    value: SymbolicList,
    needle: object,
    constraints: list[z3.BoolRef] | None = None,
) -> SymbolicList | None:
    """Return an exact sequence after removing the first definitely matching item."""
    items = exact_concrete_items(value, constraints)
    if items is None:
        return None
    for index, item in enumerate(items):
        if _retained_items_definitely_equal(item, needle):
            updated = list(items)
            del updated[index]
            return SymbolicList.from_const(updated)
    return None


def insert_retained_sequence_item(
    value: SymbolicList,
    index: object,
    item: object,
    constraints: list[z3.BoolRef] | None = None,
) -> SymbolicList | None:
    """Return an exact sequence after CPython-faithful retained insertion."""
    items = exact_concrete_items(value, constraints)
    if items is None:
        return None
    insert_index = normalize_insert_index(index, len(items))
    if insert_index is None:
        return None
    updated_items = list(items)
    updated_items.insert(insert_index, item)
    return SymbolicList.from_const(updated_items)


def normalize_insert_index(index: object, length: int) -> int | None:
    """Normalize a concrete ``list.insert`` index using CPython bounds behavior."""
    raw_index = _concrete_int_value(index)
    if raw_index is None:
        return None
    if raw_index < 0:
        return max(0, raw_index + length)
    return min(raw_index, length)


def reverse_retained_sequence(
    value: SymbolicList,
    constraints: list[z3.BoolRef] | None = None,
) -> SymbolicList | None:
    """Return an exact retained sequence with item order reversed."""
    items = exact_concrete_items(value, constraints)
    if items is None:
        return None
    return SymbolicList.from_const(list(reversed(items)))


def sort_retained_sequence(
    value: SymbolicList,
    reverse: object = False,
    constraints: list[z3.BoolRef] | None = None,
) -> SymbolicList | None:
    """Return an exact CPython-sorted retained sequence when ordering is known."""
    items = exact_concrete_items(value, constraints)
    reverse_flag = concrete_bool_value(reverse)
    if items is None or reverse_flag is None:
        return None
    sortable_items = cast("list[Any]", list(items))
    try:
        sortable_items.sort(reverse=reverse_flag)
    except TypeError:
        return None
    return SymbolicList.from_const(list(sortable_items))


def retained_sequence_index_result(
    value: SymbolicList,
    needle: object,
    constraints: list[z3.BoolRef] | None = None,
    start: object = _MISSING_INDEX_BOUND,
    stop: object = _MISSING_INDEX_BOUND,
) -> RetainedSequenceIndexResult | None:
    """Return exact ``sequence.index(needle[, start[, stop]])`` semantics."""
    items = exact_concrete_items(value, constraints)
    if items is None:
        return None
    bounds = _normalized_index_bounds(len(items), start, stop)
    if bounds is None:
        return None

    needle_value = _sequence_needle_value(needle)
    if needle_value is None:
        return None

    start_index, stop_index = bounds
    matches: list[tuple[int, z3.BoolRef]] = []
    for index, item in enumerate(items[start_index:stop_index], start=start_index):
        condition = retained_item_equality_condition(needle_value, item)
        if condition is None:
            return None
        matches.append((index, condition))

    found_condition = simplify_expr(
        z3.Or(*(condition for _, condition in matches)) if matches else Z3_FALSE,
    )
    index_expr = _first_match_index_expr(matches)
    return RetainedSequenceIndexResult(
        value=SymbolicValue(
            _name=f"{getattr(value, 'name', 'sequence')}.index({getattr(needle, 'name', needle)!s})",
            z3_int=index_expr,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_str=Z3_FALSE,
            is_none=Z3_FALSE,
            affinity_type="int",
        ),
        found_condition=found_condition,
    )


def retained_sequence_item_for_index(
    value: SymbolicList,
    index: object,
    state: VMState,
    *,
    name: str | None = None,
) -> RetainedSequenceItemResult | None:
    """Return an exact finite retained item when the current path proves an index valid."""
    constraints = state.path_constraints.to_list()
    items = exact_concrete_items(value, constraints)
    if items is None:
        return None
    if not items:
        return None

    concrete_index = concrete_sequence_index(index, len(items))
    if concrete_index is not None:
        return RetainedSequenceItemResult(
            value=_stack_value_from_retained_item(items[concrete_index]),
            item_condition=Z3_TRUE,
        )

    symbolic_index = sequence_index_value(index)
    if symbolic_index is None:
        return None
    possible_items = retained_sequence_possible_items(
        items,
        symbolic_index.z3_int,
        state,
    )
    if possible_items is None:
        return None
    if len(possible_items) == 1:
        condition, item = possible_items[0]
        return RetainedSequenceItemResult(
            value=_stack_value_from_retained_item(item),
            item_condition=condition,
        )

    item_name = name or f"{value.name}[{symbolic_index.name}]"
    string_value = _conditional_string_item(item_name, possible_items)
    if string_value is not None:
        return RetainedSequenceItemResult(
            value=string_value,
            item_condition=simplify_expr(z3.Or(*(condition for condition, _ in possible_items))),
        )

    int_value = _conditional_int_item(item_name, possible_items)
    if int_value is not None:
        return RetainedSequenceItemResult(
            value=int_value,
            item_condition=simplify_expr(z3.Or(*(condition for condition, _ in possible_items))),
        )
    return None


def retained_sequence_possible_items(
    items: list[object],
    index: z3.ArithRef,
    state: VMState,
) -> list[tuple[z3.BoolRef, object]] | None:
    """Return retained items whose normalized indexes are feasible on this path."""
    length = len(items)
    possible_items: list[tuple[z3.BoolRef, object]] = []
    for position, item in enumerate(items):
        condition = simplify_expr(normalized_index_alias(index, position, length))
        if not _path_refutes(state, condition):
            possible_items.append((condition, item))

    if not possible_items:
        return None
    valid_index = simplify_expr(z3.Or(*(condition for condition, _item in possible_items)))
    if not _path_implies(state, valid_index):
        return None
    return possible_items


def concrete_sequence_index(index: object, length: int) -> int | None:
    """Normalize a concrete Python sequence index, or return ``None`` when unavailable."""
    value = _concrete_int_value(index)
    if value is None:
        return None
    return normalize_concrete_index(value, length)


def sequence_index_value(index: object) -> SymbolicValue | None:
    """Return the symbolic integer carrier for a CPython sequence index operand."""
    if isinstance(index, bool | int):
        return SymbolicValue.from_const(int(index))
    if isinstance(index, SymbolicValue):
        return index
    return None


def sequence_index_error_condition(value: SymbolicList, index: SymbolicValue) -> z3.BoolRef:
    """Return the condition under which a sequence index is out of bounds."""
    return simplify_expr(z3.Or(index.z3_int >= value.z3_len, index.z3_int < -value.z3_len))


def normalize_concrete_index(index: int, length: int) -> int | None:
    """Normalize a CPython sequence index or return ``None`` when out of bounds."""
    normalized = index if index >= 0 else index + length
    if 0 <= normalized < length:
        return normalized
    return None


def normalized_index_alias(index: z3.ArithRef, item_index: int, length: int) -> z3.BoolRef:
    """Return raw index values that select one normalized finite sequence item."""
    negative_index = item_index - length
    if negative_index < 0:
        return z3.Or(index == item_index, index == negative_index)
    return index == item_index


def exact_index_from_constraints(
    index: z3.ArithRef,
    length: int,
    constraints: list[z3.BoolRef],
) -> int | None:
    """Return a uniquely equality-pinned sequence index from path constraints."""
    candidates: set[int] = set()
    for constraint in reversed(constraints):
        candidate = _exact_index_equality_candidate(index, constraint, length)
        if candidate is not None:
            candidates.add(candidate)
            if len(candidates) > 1:
                return None
    if len(candidates) == 1:
        return candidates.pop()
    return None


def retained_item_equality_condition(
    value: SymbolicValue | SymbolicString,
    item: object,
) -> z3.BoolRef | None:
    """Return Python equality against a retained sequence item."""
    if isinstance(value, SymbolicString):
        if isinstance(item, SymbolicValue):
            return z3.And(item.is_str, value.z3_str == item.z3_str)
        if isinstance(item, SymbolicString):
            return value.z3_str == item.z3_str
        if isinstance(item, str):
            return value.z3_str == ConstraintValues.string(item)
        return Z3_FALSE

    if isinstance(item, SymbolicString):
        return z3.And(value.is_str, value.z3_str == item.z3_str)
    if isinstance(item, SymbolicValue):
        return z3.Or(
            z3.And(value.is_none, item.is_none),
            z3.And(value.is_bool, item.is_bool, value.z3_bool == item.z3_bool),
            z3.And(value.is_int, item.is_int, value.z3_int == item.z3_int),
            z3.And(value.is_str, item.is_str, value.z3_str == item.z3_str),
            z3.And(
                value.is_bool,
                item.is_int,
                z3.If(value.z3_bool, Z3_ONE, Z3_ZERO) == item.z3_int,
            ),
            z3.And(
                value.is_int,
                item.is_bool,
                value.z3_int == z3.If(item.z3_bool, Z3_ONE, Z3_ZERO),
            ),
        )
    if item is None:
        return value.is_none
    if isinstance(item, bool):
        concrete_bool = Z3_TRUE if item else Z3_FALSE
        return z3.Or(
            z3.And(value.is_bool, value.z3_bool == concrete_bool),
            z3.And(value.is_int, value.z3_int == int(item)),
        )
    if isinstance(item, int):
        conditions = [z3.And(value.is_int, value.z3_int == item)]
        if item in (0, 1):
            concrete_bool = Z3_TRUE if item else Z3_FALSE
            conditions.append(z3.And(value.is_bool, value.z3_bool == concrete_bool))
        return z3.Or(*conditions)
    if isinstance(item, str):
        return z3.And(value.is_str, value.z3_str == ConstraintValues.string(item))
    return None


def _bool_value(name: str, condition: z3.BoolRef) -> SymbolicValue:
    return SymbolicValue(
        _name=name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=simplify_expr(condition),
        is_bool=Z3_TRUE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="bool",
    )


def _sequence_needle_value(needle: object) -> SymbolicValue | SymbolicString | None:
    if isinstance(needle, SymbolicValue | SymbolicString):
        return needle
    if needle is None or isinstance(needle, bool | int | str):
        return SymbolicValue.from_const(needle)
    return None


def _concrete_int_value(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, SymbolicValue):
        concrete = value.value
        if isinstance(concrete, bool):
            return int(concrete)
        if isinstance(concrete, int):
            return concrete
        expr = simplify_expr(value.z3_int)
        if z3.is_int_value(expr):
            return expr.as_long()
    return None


def concrete_bool_value(value: object) -> bool | None:
    """Return a concrete boolean stack value when it is definitely known."""
    if isinstance(value, bool):
        return value
    if isinstance(value, SymbolicValue):
        concrete = value.value
        if isinstance(concrete, bool):
            return concrete
        expr = simplify_expr(value.z3_bool)
        if z3.is_true(expr):
            return True
        if z3.is_false(expr):
            return False
    return None


def _retained_items_definitely_equal(left: object, right: object) -> bool:
    if left is right:
        return True
    left_value = _primitive_retained_constant(left)
    right_value = _primitive_retained_constant(right)
    return left_value is not _UNKNOWN_RETAINED_ITEM and left_value == right_value


_UNKNOWN_RETAINED_ITEM = object()


def _primitive_retained_constant(value: object) -> object:
    if isinstance(value, SymbolicValue):
        concrete = value.value
        if isinstance(concrete, bool | int | str | bytes) or concrete is None:
            return concrete
        return _UNKNOWN_RETAINED_ITEM
    if isinstance(value, bool | int | str | bytes) or value is None:
        return value
    return _UNKNOWN_RETAINED_ITEM


def _stack_value_from_retained_item(item: object) -> StackValue:
    if item is None:
        return SymbolicNoneType()
    return cast("StackValue", item)


def _conditional_string_item(
    name: str,
    possible_items: list[tuple[z3.BoolRef, object]],
) -> SymbolicString | None:
    selected_str: z3.SeqRef | None = None
    selected_len: z3.ArithRef | None = None
    for condition, item in reversed(possible_items):
        item_str, item_len = _string_item_channels(item)
        if item_str is None or item_len is None:
            return None
        if selected_str is None or selected_len is None:
            selected_str = item_str
            selected_len = item_len
            continue
        selected_str = z3.If(condition, item_str, selected_str)
        selected_len = z3.If(condition, item_len, selected_len)

    if selected_str is None or selected_len is None:
        return None
    return SymbolicString(
        _z3_str=simplify_expr(selected_str),
        _z3_len=simplify_expr(selected_len),
        _name=name,
    )


def _conditional_int_item(
    name: str,
    possible_items: list[tuple[z3.BoolRef, object]],
) -> SymbolicValue | None:
    last_value = _int_like_item(possible_items[-1][1])
    if last_value is None:
        return None

    result_expr = last_value.z3_int
    for condition, item in reversed(possible_items[:-1]):
        symbolic_item = _int_like_item(item)
        if symbolic_item is None:
            return None
        result_expr = z3.If(condition, symbolic_item.z3_int, result_expr)

    return SymbolicValue(
        _name=name,
        z3_int=simplify_expr(result_expr),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )


def _int_like_item(item: object) -> SymbolicValue | None:
    symbolic = item if isinstance(item, SymbolicValue) else SymbolicValue.from_const(item)
    if symbolic.affinity_type in {"int", "bool"}:
        return symbolic
    if z3.is_true(simplify_expr(symbolic.is_int)) or z3.is_true(simplify_expr(symbolic.is_bool)):
        return symbolic
    return None


def _string_item_channels(item: object) -> tuple[z3.SeqRef | None, z3.ArithRef | None]:
    if isinstance(item, str):
        return ConstraintValues.string(item), ConstraintValues.int(len(item))
    if isinstance(item, SymbolicString):
        return item.z3_str, item.z3_len
    if isinstance(item, SymbolicValue) and z3.is_true(simplify_expr(item.is_str)):
        return item.z3_str, z3.Length(item.z3_str)
    return None, None


def _path_refutes(state: VMState, condition: z3.BoolRef) -> bool:
    simplified = simplify_expr(condition)
    if z3.is_false(simplified):
        return True
    if z3.is_true(simplified):
        return False
    constraints = [*state.path_constraints.to_list(), simplified]
    known_prefix_len = _known_sat_prefix_len(state)
    if not path_may_be_feasible(
        constraints,
        known_sat_prefix_len=known_prefix_len,
    ):
        return True
    return _local_solver_proves_unsat(constraints)


def _local_solver_proves_unsat(constraints: list[z3.BoolRef]) -> bool:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.unsat


def _path_implies(state: VMState, condition: z3.BoolRef) -> bool:
    simplified = simplify_expr(condition)
    if z3.is_true(simplified):
        return True
    if z3.is_false(simplified):
        return False
    return _path_refutes(state, z3.Not(simplified))


def _known_sat_prefix_len(state: VMState) -> int:
    return max(0, len(state.path_constraints) - state.pending_constraint_count)


def _exact_index_equality_candidate(
    index: z3.ArithRef,
    constraint: z3.BoolRef,
    length: int,
) -> int | None:
    if not z3.is_eq(constraint) or constraint.num_args() != 2:
        return None
    left = constraint.arg(0)
    right = constraint.arg(1)
    if Z3ExpressionOps.safe_eq(left, index) and z3.is_int_value(right):
        return normalize_concrete_index(right.as_long(), length)
    if Z3ExpressionOps.safe_eq(right, index) and z3.is_int_value(left):
        return normalize_concrete_index(left.as_long(), length)
    return None


def _normalized_index_bounds(
    length: int,
    start: object,
    stop: object,
) -> tuple[int, int] | None:
    start_value = _concrete_index_bound(start, default=0)
    stop_value = _concrete_index_bound(stop, default=length)
    if start_value is None or stop_value is None:
        return None
    return (
        _normalize_index_bound(start_value, length),
        _normalize_index_bound(stop_value, length),
    )


def _concrete_index_bound(value: object, *, default: int) -> int | None:
    if value is _MISSING_INDEX_BOUND:
        return default
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _normalize_index_bound(value: int, length: int) -> int:
    if value < 0:
        return max(value + length, 0)
    return min(value, length)


def _first_match_index_expr(matches: list[tuple[int, z3.BoolRef]]) -> z3.ArithRef:
    result: z3.ArithRef = Z3_ZERO
    for index, condition in reversed(matches):
        result = z3.If(condition, z3.IntVal(index), result)
    return simplify_expr(result)


def derived_concrete_items(
    value: SymbolicList,
    constraints: list[z3.BoolRef] | None = None,
) -> list[object] | None:
    """Materialize derived exact sequences once path constraints force their source."""
    if getattr(value, "_derived_sequence_kind", None) != PATH_SUFFIXES_SEQUENCE_KIND:
        return None
    source_str = getattr(value, "_derived_source_str", None)
    if not isinstance(source_str, z3.SeqRef):
        return None
    literal = _forced_string_literal(source_str, constraints)
    if literal is None:
        return None
    return list(PurePosixPath(literal).suffixes)


def _forced_string_literal(
    expression: z3.SeqRef,
    constraints: list[z3.BoolRef] | None,
) -> str | None:
    if z3.is_string_value(expression):
        try:
            return expression.as_string()
        except z3.Z3Exception:
            return None
    if not constraints:
        return None
    for constraint in constraints:
        literal = _literal_from_string_equality(expression, simplify_expr(constraint))
        if literal is not None:
            return literal
    return None


def _literal_from_string_equality(expression: z3.SeqRef, constraint: z3.BoolRef) -> str | None:
    try:
        if not z3.is_eq(constraint):
            return None
        left, right = constraint.children()
    except (ValueError, z3.Z3Exception):
        return None
    if isinstance(left, z3.SeqRef) and z3.eq(left, expression):
        return _string_literal(right)
    if isinstance(right, z3.SeqRef) and z3.eq(right, expression):
        return _string_literal(left)
    return None


def _string_literal(value: z3.ExprRef) -> str | None:
    if not z3.is_string_value(value):
        return None
    try:
        return value.as_string()
    except z3.Z3Exception:
        return None


def concrete_repeat_count(value: object) -> int | None:
    """Return a concrete sequence repeat count when one is definitely known."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if not isinstance(value, SymbolicValue):
        return None
    concrete = value.value
    if isinstance(concrete, bool):
        return int(concrete)
    if isinstance(concrete, int):
        return concrete
    expr = simplify_expr(value.z3_int)
    if z3.is_int_value(expr):
        return expr.as_long()
    return None


def repeat_count_expr(value: object) -> z3.ArithRef | None:
    """Return an arithmetic repeat-count expression for concrete or symbolic integers."""
    if isinstance(value, bool):
        return Z3_ONE if value else Z3_ZERO
    if isinstance(value, int):
        return ConstraintValues.int(value)
    if isinstance(value, SymbolicValue):
        return value.z3_int
    return None
