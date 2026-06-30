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

"""Domain-owned policy namespaces for core builtin function models."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeGuard

import z3

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.guards import RuntimeObjectGuards
from pysymex._internal.models.builtins.iteration.sort_precision import safe_sorted_modeled_instances

_ConcreteNumeric = int | float | bool


def _is_numeric_sequence(values: Sequence[object]) -> TypeGuard[Sequence[_ConcreteNumeric]]:
    return all(isinstance(x, (int, float, bool)) for x in values)


def _is_str_sequence(values: Sequence[object]) -> TypeGuard[Sequence[str]]:
    return all(isinstance(x, str) for x in values)


def _is_bytes_sequence(values: Sequence[object]) -> TypeGuard[Sequence[bytes]]:
    return all(isinstance(x, bytes) for x in values)


def _is_frozenset_of_objects(value: object) -> TypeGuard[frozenset[object]]:
    return isinstance(value, frozenset)


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


class BuiltinInputPolicy:
    """Classify builtin argument shapes and definite input failures."""

    @staticmethod
    def constant_len(value: object) -> int | None:
        """Return CPython length for concrete payloads, including symbolic constants."""
        if isinstance(value, SymbolicValue):
            value = value.value
        if isinstance(value, SymbolicList) and value.concrete_items is not None:
            return len(value.concrete_items)
        if isinstance(value, (str, bytes, range)):
            return len(value)
        if RuntimeObjectGuards.list(value) or RuntimeObjectGuards.tuple(value):
            return len(value)
        if RuntimeObjectGuards.dict(value):
            return len(value)
        if RuntimeObjectGuards.set(value) or _is_frozenset_of_objects(value):
            return len(value)
        return None

    @staticmethod
    def len_type_error(value: object) -> bool:
        if isinstance(value, (int, float, bool)) or value is None:
            return True
        if isinstance(value, SymbolicValue):
            if "[" in value.name or "]" in value.name:
                return False
            # Affinity is a hint, not proof that a union-like value cannot be
            # refined to a string, container, or modeled object on this path.
            if any(
                not z3.is_false(type_predicate)
                for type_predicate in (value.is_str, value.is_list, value.is_dict, value.is_obj)
            ):
                return False
            return value.affinity_type in {"int", "float", "bool", "none"}
        return False

    @staticmethod
    def iter_type_error(value: object) -> bool:
        if isinstance(value, (int, float, bool)) or value is None:
            return True
        if isinstance(value, SymbolicValue):
            from pysymex._internal.core.calls.payload import function_payload

            if function_payload(getattr(value, "_modeled_object", value)) is not None:
                return False
            return value.affinity_type in {"int", "float", "bool", "none"}
        return False

    @staticmethod
    def definite_ordering_type_error(values: Sequence[object]) -> bool:
        """Return whether exact builtin scalar values definitely fail CPython ordering."""
        safe_types = (int, float, bool, str, bytes)
        if not values or not all(type(value) in safe_types for value in values):
            return False
        categories = {
            "numeric" if type(value) in (int, float, bool) else type(value).__name__
            for value in values
        }
        return len(categories) > 1


class BuiltinAggregatePolicy:
    """Compute concrete aggregate results for min/max/sorted/sum builtins."""

    @staticmethod
    def safe_min_concrete(values: Sequence[StackValue]) -> StackValue:
        if _is_numeric_sequence(values):
            return min(values)
        if _is_str_sequence(values):
            return min(values)
        if _is_bytes_sequence(values):
            return min(values)
        return None

    @staticmethod
    def safe_max_concrete(values: Sequence[StackValue]) -> StackValue:
        if _is_numeric_sequence(values):
            return max(values)
        if _is_str_sequence(values):
            return max(values)
        if _is_bytes_sequence(values):
            return max(values)
        return None

    @staticmethod
    def safe_sorted_concrete(
        values: Sequence[StackValue],
        *,
        reverse: bool,
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

    @staticmethod
    def safe_sum_concrete(values: Sequence[StackValue], start: StackValue) -> StackValue:
        if not isinstance(start, (int, float, bool)):
            return None
        if not _is_numeric_sequence(values):
            return None
        return sum(values, start)
