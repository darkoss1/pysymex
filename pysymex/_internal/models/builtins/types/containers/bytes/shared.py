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

"""Shared helpers for symbolic bytes and bytearray models."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.bytes_search import concrete_bytes_search_literal
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.models.contracts.results import ModelResult


def get_symbolic_bytes(arg: object, state: VMState | None = None) -> SymbolicList | None:
    """Extract SymbolicList storage used for bytes/bytearray-like models."""
    return SymbolicList.resolve_bytes(arg, state)


def symbolic_bytes_length(arg: object, state: VMState | None = None) -> z3.ArithRef | None:
    """Return a modeled bytes/bytearray length expression when available."""
    if isinstance(arg, SymbolicBytes):
        return arg.z3_len
    storage = get_symbolic_bytes(arg, state)
    if storage is not None:
        return storage.z3_len
    if isinstance(arg, SymbolicValue):
        return arg.symbolic_length()
    return None


def concrete_bytes_literal(arg: object) -> bytes | None:
    """Return concrete bytes when a bytes-like symbolic list is exact."""
    return concrete_bytes_search_literal(arg)


def symbolic_bytes_literal(value: bytes) -> SymbolicList:
    """Return a concrete-backed symbolic bytes value from exact bytes."""
    result = SymbolicList.from_const(list(value))
    return dataclasses.replace(result, _type="bytes")


def symbolic_bytes_items(values: Sequence[object]) -> SymbolicList:
    """Return a bytes-typed symbolic list retaining exact finite items."""
    result = SymbolicList.from_const(values)
    return dataclasses.replace(result, _type="bytes")


def bytearray_result(result: ModelResult) -> ModelResult:
    """Retag symbolic-list model results as bytearray values."""
    if isinstance(result.value, SymbolicList):
        result.value.set_runtime_type("bytearray")
    return result


def bytearray_elements_result(result: ModelResult) -> ModelResult:
    """Retag exact symbolic-list elements in split-style results as bytearray values."""
    if isinstance(result.value, SymbolicList) and result.value.concrete_items is not None:
        for item in result.value.concrete_items:
            if isinstance(item, SymbolicList):
                item.set_runtime_type("bytearray")
    return result
