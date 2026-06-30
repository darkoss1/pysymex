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

"""Fast-path lowering for subscripts on concrete list, tuple, str, bytes, and dict.

Returns :class:`~pysymex._internal.execution.opcodes.common.lowering.types.LoweredValue`
when indices and keys are concrete; otherwise returns ``None`` so callers apply
symbolic subscript logic. Out-of-range accesses attach exception conditions
rather than terminating exploration silently.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.lowering.types import LoweredValue

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


def lower_concrete_subscript(
    pc: int,
    container: object,
    index: StackValue,
) -> LoweredValue | None:
    """Lower subscripts on concrete containers when the index is an integer constant."""
    if isinstance(container, (list, tuple, str, bytes)):
        concrete_container = cast("list[object] | tuple[object, ...] | str | bytes", container)
        concrete_index = concrete_int_index(index)
        if concrete_index is None:
            return None
        try:
            return LoweredValue(to_stack_value(concrete_container[concrete_index]))
        except IndexError:
            result, constraint = SymbolicValue.symbolic(f"subscr_error_{pc}")
            return LoweredValue(result, constraints=[constraint], exception_condition=Z3_TRUE)
        except TypeError:
            return None

    if isinstance(container, dict):
        concrete_mapping = cast("dict[object, object]", container)
        concrete_key_value = concrete_key(index)
        if concrete_key_value is None:
            return None
        try:
            return LoweredValue(to_stack_value(concrete_mapping[concrete_key_value]))
        except KeyError:
            result, constraint = SymbolicValue.symbolic(f"subscr_error_{pc}")
            return LoweredValue(result, constraints=[constraint], exception_condition=Z3_TRUE)
        except TypeError:
            return None

    return None


def concrete_int_index(index: StackValue) -> int | None:
    """Extract a concrete integer index from stack values when possible."""
    if isinstance(index, bool):
        return int(index)
    if isinstance(index, int):
        return index
    if isinstance(index, SymbolicValue):
        value = index.value
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        simplified_index = simplify_expr(index.z3_int)
        if z3.is_int_value(simplified_index):
            return simplified_index.as_long()
    return None


def concrete_key(key: StackValue) -> object | None:
    """Extract a hashable concrete dict key from symbolic or runtime keys."""
    if isinstance(key, SymbolicString) and z3.is_string_value(key.z3_str):
        return key.z3_str.as_string()
    if isinstance(key, SymbolicValue):
        value = key.value
        if value is not None:
            return value
        if z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        if z3.is_int_value(key.z3_int):
            return key.z3_int.as_long()
        return None
    if isinstance(key, tuple):
        return cast("tuple[object, ...]", key)
    if isinstance(key, frozenset):
        return cast("frozenset[object]", key)
    if isinstance(key, (str, int, bool, bytes, float, type(None))):
        return key
    return None


def to_stack_value(value: object) -> StackValue:
    """Promote lowered concrete results into VM stack values."""
    if value is None:
        return None
    if isinstance(
        value,
        (
            SymbolicValue,
            SymbolicString,
            SymbolicList,
            SymbolicDict,
            SymbolicObject,
            ModeledGenerator,
            int,
            bool,
            str,
            float,
            bytes,
            type,
            list,
            dict,
            tuple,
        ),
    ):
        return cast("StackValue", value)
    if callable(value):
        return cast("StackValue", value)
    return SymbolicValue.from_const(value)
