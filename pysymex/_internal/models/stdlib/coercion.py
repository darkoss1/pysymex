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

"""Coercion and symbolic creation helper functions for stdlib models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


def symbolic_object(name: str, type_name: str) -> tuple[SymbolicValue, z3.BoolRef]:
    value, constraint = SymbolicValue.symbolic(name)
    value.set_runtime_type(type_name)
    return value, z3.And(constraint, value.is_obj)


def symbolic_int_range(name: str, lower: int | None, upper: int | None) -> ModelResult:
    value, constraint = SymbolicValue.symbolic_int(name)
    constraints: list[z3.BoolRef] = [constraint]
    if lower is not None:
        constraints.append(value.z3_int >= lower)
        value.min_val = lower
    if upper is not None:
        constraints.append(value.z3_int <= upper)
        value.max_val = upper
    return ModelResult(value=value, constraints=constraints)


def const_string(value: StackValue) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString) and z3.is_string_value(value.z3_str):
        return value.z3_str.as_string()
    if isinstance(value, SymbolicValue) and isinstance(value.value, str):
        return value.value
    return None


def const_bytes(value: StackValue) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, SymbolicBytes):
        return value.concrete_value
    if isinstance(value, SymbolicValue) and isinstance(value.value, bytes):
        return value.value
    return None


def const_int(value: StackValue) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, SymbolicValue) and isinstance(value.value, int):
        return value.value
    return None


def const_float(value: StackValue) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, SymbolicValue) and isinstance(value.value, (int, float)):
        return float(value.value)
    return None


def literal_text_or_bytes(value: StackValue) -> str | bytes | None:
    text = const_string(value)
    if text is not None:
        return text
    return const_bytes(value)


def dict_from_mapping(values: dict[str, object]) -> SymbolicDict:
    return SymbolicDict.from_const(cast("dict[object, object]", values))
