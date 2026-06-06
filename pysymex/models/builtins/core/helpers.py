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

"""Shared helpers for core builtin function models."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, TypeGuard

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.typing import (
    is_dict_of_objects,
    is_list_of_objects,
    is_set_of_objects,
    is_tuple_of_objects,
)
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.sort_precision import safe_sorted_modeled_instances

_ConcreteNumeric = int | float | bool


def _is_numeric_sequence(values: Sequence[object]) -> TypeGuard[Sequence[_ConcreteNumeric]]:
    return all(isinstance(x, (int, float, bool)) for x in values)


def _is_str_sequence(values: Sequence[object]) -> TypeGuard[Sequence[str]]:
    return all(isinstance(x, str) for x in values)


def _is_bytes_sequence(values: Sequence[object]) -> TypeGuard[Sequence[bytes]]:
    return all(isinstance(x, bytes) for x in values)


def _is_frozenset_of_objects(value: object) -> TypeGuard[frozenset[object]]:
    return isinstance(value, frozenset)


def safe_min_concrete(values: Sequence[StackValue]) -> StackValue:
    if _is_numeric_sequence(values):
        return min(values)
    if _is_str_sequence(values):
        return min(values)
    if _is_bytes_sequence(values):
        return min(values)
    return None


def safe_max_concrete(values: Sequence[StackValue]) -> StackValue:
    if _is_numeric_sequence(values):
        return max(values)
    if _is_str_sequence(values):
        return max(values)
    if _is_bytes_sequence(values):
        return max(values)
    return None


def safe_sorted_concrete(
    values: Sequence[StackValue], *, reverse: bool
) -> Sequence[StackValue] | None:
    numeric_payloads = _numeric_payloads(values)
    if numeric_payloads is not None:
        return _sort_by_numeric_payload(values, numeric_payloads, reverse=reverse)
    str_payloads = _str_payloads(values)
    if str_payloads is not None:
        return _sort_by_str_payload(values, str_payloads, reverse=reverse)
    bytes_payloads = _bytes_payloads(values)
    if bytes_payloads is not None:
        return _sort_by_bytes_payload(values, bytes_payloads, reverse=reverse)
    modeled_items = safe_sorted_modeled_instances(values, reverse=reverse)
    if modeled_items is not None:
        return modeled_items
    return None


def _numeric_payloads(values: Sequence[StackValue]) -> list[_ConcreteNumeric] | None:
    """Return retained numeric payloads when every item has one."""
    payloads: list[_ConcreteNumeric] = []
    for value in values:
        payload = value.value if isinstance(value, SymbolicValue) else value
        if not isinstance(payload, (int, float, bool)):
            return None
        payloads.append(payload)
    return payloads


def _str_payloads(values: Sequence[StackValue]) -> list[str] | None:
    """Return retained string payloads when every item has one."""
    payloads: list[str] = []
    for value in values:
        payload = value.value if isinstance(value, SymbolicValue) else value
        if not isinstance(payload, str):
            return None
        payloads.append(payload)
    return payloads


def _bytes_payloads(values: Sequence[StackValue]) -> list[bytes] | None:
    """Return retained bytes payloads when every item has one."""
    payloads: list[bytes] = []
    for value in values:
        payload = value.value if isinstance(value, SymbolicValue) else value
        if not isinstance(payload, bytes):
            return None
        payloads.append(payload)
    return payloads


def _sort_by_numeric_payload(
    values: Sequence[StackValue],
    payloads: Sequence[_ConcreteNumeric],
    *,
    reverse: bool,
) -> Sequence[StackValue] | None:
    """Sort stack values by retained numeric CPython payloads."""
    try:
        indexes = sorted(range(len(values)), key=lambda index: payloads[index], reverse=reverse)
    except TypeError:
        return None
    return [values[index] for index in indexes]


def _sort_by_str_payload(
    values: Sequence[StackValue],
    payloads: Sequence[str],
    *,
    reverse: bool,
) -> Sequence[StackValue] | None:
    """Sort stack values by retained string CPython payloads."""
    try:
        indexes = sorted(range(len(values)), key=lambda index: payloads[index], reverse=reverse)
    except TypeError:
        return None
    return [values[index] for index in indexes]


def _sort_by_bytes_payload(
    values: Sequence[StackValue],
    payloads: Sequence[bytes],
    *,
    reverse: bool,
) -> Sequence[StackValue] | None:
    """Sort stack values by retained bytes CPython payloads."""
    try:
        indexes = sorted(range(len(values)), key=lambda index: payloads[index], reverse=reverse)
    except TypeError:
        return None
    return [values[index] for index in indexes]


def value_error_side_effect(source: str, message: str) -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "VALUE_ERROR",
            "exception_type": "ValueError",
            "message": message,
            "source": source,
        }
    }


def zero_division_error_side_effect(source: str, message: str) -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "ZERO_DIVISION_ERROR",
            "exception_type": "ZeroDivisionError",
            "message": message,
            "source": source,
        }
    }


def type_error_side_effect(source: str, message: str) -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "TYPE_ERROR",
            "exception_type": "TypeError",
            "message": message,
            "source": source,
        }
    }


def symbolic_list_len_is_zero(value: SymbolicList) -> bool:
    return z3.is_true(z3.simplify(value.z3_len == 0))


def known_len_type_error(value: object) -> bool:
    if isinstance(value, (int, float, bool)) or value is None:
        return True
    if isinstance(value, SymbolicValue):
        if "[" in value.name or "]" in value.name:
            return False
        return value.affinity_type in {"int", "float", "bool", "none", "NoneType"}
    return False


def known_iter_type_error(value: object) -> bool:
    if isinstance(value, (int, float, bool)) or value is None:
        return True
    if isinstance(value, SymbolicValue):
        from pysymex.execution.calls.payload import function_payload

        if function_payload(getattr(value, "_modeled_object", value)) is not None:
            return False
        return value.affinity_type in {"int", "float", "bool", "none", "NoneType"}
    return False


def resolve_heap_object(value: object, state: VMState) -> object:
    if isinstance(value, SymbolicObject) and value.address != -1:
        resolved = state.memory.get(value.address)
        if resolved is not None:
            return resolved
    return value


def safe_sum_concrete(values: Sequence[StackValue], start: StackValue) -> StackValue:
    if not isinstance(start, (int, float, bool)):
        return None
    if not _is_numeric_sequence(values):
        return None
    return sum(values, start)


def constant_len(value: object) -> int | None:
    """Return CPython length for concrete payloads, including symbolic constants."""
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, SymbolicList) and value.concrete_items is not None:
        return len(value.concrete_items)
    if isinstance(value, (str, bytes, range)):
        return len(value)
    if is_list_of_objects(value) or is_tuple_of_objects(value):
        return len(value)
    if is_dict_of_objects(value):
        return len(value)
    if is_set_of_objects(value) or _is_frozenset_of_objects(value):
        return len(value)
    return None
