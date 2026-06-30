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

"""Stack-value, keyword-name, and Z3 coercion helpers for calls."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType, SymbolicType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    import z3

    from pysymex._internal.typing.protocols import StackValue


def concrete_string(value: object) -> str | None:
    """Return a concrete Python string when *value* is known at analysis time."""
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString):
        raw_name = value.name
        if len(raw_name) >= 2 and raw_name[0] == raw_name[-1] and raw_name[0] in {"'", '"'}:
            return raw_name[1:-1]
        return None
    if isinstance(value, SymbolicValue) and isinstance(value.value, str):
        return value.value
    return None


def to_z3_expr(value: StackValue) -> z3.ExprRef | None:
    """Best-effort conversion from stack values to Z3 expressions."""
    if isinstance(value, SymbolicValue):
        return value.to_z3()
    if isinstance(value, int) and not isinstance(value, bool):
        return ConstraintValues.int(value)
    if isinstance(value, bool):
        return Z3_TRUE if value else Z3_FALSE
    if isinstance(value, float):
        return ConstraintValues.real(value)
    if isinstance(value, str):
        return ConstraintValues.string(value)
    return None


def coerce_call_stack_value(value: object) -> StackValue:
    """Best-effort conversion into the StackValue domain used by VMState."""
    if value is None:
        return None
    try:
        from pysymex._internal.core.classes.types import SymbolicMethod
    except ImportError:
        SymbolicMethod = None
    if SymbolicMethod is not None and isinstance(value, SymbolicMethod):
        return cast("StackValue", value)
    if isinstance(value, list):
        return SymbolicList.from_const(cast("list[object]", value))
    if isinstance(
        value,
        (
            SymbolicValue,
            SymbolicNoneType,
            SymbolicString,
            SymbolicList,
            SymbolicDict,
            SymbolicObject,
            ModeledGenerator,
            SymbolicType,
            int,
            bool,
            str,
            float,
            bytes,
            type,
            dict,
            tuple,
        ),
    ):
        return cast("StackValue", value)
    if callable(value):
        return cast("StackValue", value)
    return SymbolicValue.from_const(value)


def coerce_kw_names(raw_kw_names: object) -> tuple[str, ...]:
    """Normalize keyword name payloads into a tuple of keyword names."""
    if isinstance(raw_kw_names, SymbolicValue):
        constant_value: object = raw_kw_names.value
        if isinstance(constant_value, tuple):
            raw_kw_names = cast("tuple[object, ...]", constant_value)
    if isinstance(raw_kw_names, SymbolicTuple):
        names = [concrete_string(item) for item in raw_kw_names.elements]
        return tuple(name for name in names if name is not None)
    if isinstance(raw_kw_names, tuple):
        tuple_items = cast("tuple[object, ...]", raw_kw_names)
        return tuple(name for name in tuple_items if isinstance(name, str))
    if isinstance(raw_kw_names, list):
        list_items = cast("list[object]", raw_kw_names)
        return tuple(name for name in list_items if isinstance(name, str))
    if isinstance(raw_kw_names, str):
        cleaned = raw_kw_names.strip().strip("()")
        if not cleaned:
            return ()
        if "," in cleaned:
            return tuple(part.strip() for part in cleaned.split(",") if part.strip())
        return (cleaned,)
    return ()
