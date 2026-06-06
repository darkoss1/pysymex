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

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult, NoneResultFunctionModel
from pysymex.models.containers.strings.shared import SymbolicIsasciiModel

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


def get_symbolic_bytes(arg: object, state: VMState | None = None) -> SymbolicList | None:
    """Extract SymbolicList storage used for bytes/bytearray-like models."""
    if isinstance(arg, SymbolicList):
        return arg
    if state is not None:
        from pysymex.core.types.containers.objects import SymbolicObject

        if isinstance(arg, SymbolicObject) and arg.address in state.memory:
            value = state.memory[arg.address]
            if isinstance(value, SymbolicList) and getattr(value, "_type", None) in {
                "bytes",
                "bytearray",
            }:
                return value
    return getattr(arg, "_symbolic_list", None) if arg is not None else None


def concrete_bytes_literal(arg: object) -> bytes | None:
    """Return concrete bytes when a bytes-like symbolic list is exact."""
    if isinstance(arg, bytes):
        return arg
    if isinstance(arg, SymbolicValue) and isinstance(arg.value, bytes):
        return arg.value
    b = get_symbolic_bytes(arg)
    if b is None:
        return None
    items = b.concrete_items
    if items is None:
        return None
    byte_values: list[int] = []
    for item in items:
        if not isinstance(item, int) or not 0 <= item <= 255:
            return None
        byte_values.append(item)
    return bytes(byte_values)


def symbolic_bytes_literal(value: bytes) -> SymbolicList:
    """Return a concrete-backed symbolic bytes value from exact bytes."""
    result = SymbolicList.from_const(list(value))
    return dataclasses.replace(result, _type="bytes")


def bytearray_result(result: ModelResult) -> ModelResult:
    """Retag symbolic-list model results as bytearray values."""
    if isinstance(result.value, SymbolicList):
        setattr(result.value, "_type", "bytearray")
    return result


def bytearray_elements_result(result: ModelResult) -> ModelResult:
    """Retag exact symbolic-list elements in split-style results as bytearray values."""
    if isinstance(result.value, SymbolicList) and result.value.concrete_items is not None:
        for item in result.value.concrete_items:
            if isinstance(item, SymbolicList):
                setattr(item, "_type", "bytearray")
    return result


def bytearray_type_error_result(name: str, state: VMState) -> ModelResult:
    """Return a deterministic TypeError result for an invalid bytearray method call."""
    result, constraint = SymbolicValue.symbolic(f"bytearray_{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "raised_exception": {
                "issue_kind": "TYPE_ERROR",
                "exception_type": "TypeError",
                "message": f"bytearray.{name}() received invalid arguments",
                "source": f"bytearray.{name}",
            }
        },
    )


def bytes_type_error_result(name: str, state: VMState) -> ModelResult:
    """Return a deterministic TypeError result for an invalid bytes method call."""
    result, constraint = SymbolicValue.symbolic(f"bytes_{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "raised_exception": {
                "issue_kind": "TYPE_ERROR",
                "exception_type": "TypeError",
                "message": f"bytes.{name}() received invalid arguments",
                "source": f"bytes.{name}",
            }
        },
    )


__all__ = [
    "FunctionModel",
    "ModelResult",
    "NoneResultFunctionModel",
    "SymbolicIsasciiModel",
    "SymbolicList",
    "SymbolicNone",
    "SymbolicString",
    "SymbolicValue",
    "bytearray_elements_result",
    "bytearray_result",
    "bytearray_type_error_result",
    "concrete_bytes_literal",
    "bytes_type_error_result",
    "get_symbolic_bytes",
    "symbolic_bytes_literal",
    "z3",
]
