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

"""Shared helpers for extended builtin function models."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.typing import is_list_of_objects, is_tuple_of_objects
from pysymex.core.solver.constraints.simplification import simplify_expr
from pysymex.core.solver.engine.policies import path_may_be_feasible
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from ..base import SideEffectValue


def constructor_len_expr(value: object) -> z3.ArithRef | None:
    """Return the length expression for sequence constructors that preserve input length."""
    if isinstance(value, SymbolicList):
        return value.z3_len
    if isinstance(value, SymbolicValue):
        if isinstance(value.value, int):
            return value.z3_int
        payload: object = value.value
        if is_list_of_objects(payload) or is_tuple_of_objects(payload):
            return get_int_val(len(payload))
        if isinstance(payload, (bytes, bytearray)):
            return get_int_val(len(payload))
    if isinstance(value, int):
        return get_int_val(value)
    if is_list_of_objects(value) or is_tuple_of_objects(value):
        return get_int_val(len(value))
    if isinstance(value, (bytes, bytearray)):
        return get_int_val(len(value))
    return None


def resolve_heap_object(value: object, state: VMState) -> object:
    if isinstance(value, SymbolicObject) and value.address != -1:
        resolved = state.memory.get(value.address)
        if resolved is not None:
            return resolved
    return value


def must_be_none(
    value: SymbolicValue,
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
    inconclusive_path_prefix_len: int | None = None,
) -> bool:
    """Return whether current path constraints force a symbolic value to be None."""
    if inconclusive_path_prefix_len is not None and inconclusive_path_prefix_len > 0:
        return False
    return not path_may_be_feasible(
        [*constraints, z3.Not(value.is_none)],
        known_sat_prefix_len=known_sat_prefix_len,
    )


def type_error_side_effect(source: str, message: str) -> dict[str, SideEffectValue]:
    return {
        "raised_exception": {
            "issue_kind": "TYPE_ERROR",
            "exception_type": "TypeError",
            "message": message,
            "source": source,
        }
    }


def known_iter_type_error(value: object) -> bool:
    if isinstance(value, (int, float, bool)) or value is None:
        return True
    if isinstance(value, SymbolicValue):
        from pysymex.execution.calls.payload import function_payload

        if function_payload(getattr(value, "_modeled_object", value)) is not None:
            return False
        return value.affinity_type in {"int", "float", "bool", "none", "NoneType"}
    return False


def symbolic_builtin_has_attr(value: SymbolicValue, attr_name: str) -> bool | None:
    """Return attribute presence for concretely-typed symbolic builtins, else None."""
    probes: tuple[tuple[z3.BoolRef, object], ...] = (
        (value.is_int, 0),
        (value.is_bool, False),
        (value.is_float, 0.0),
        (value.is_str, ""),
    )
    for type_flag, probe_value in probes:
        if z3.is_true(simplify_expr(type_flag)):
            return hasattr(probe_value, attr_name)
    return None


def modeled_object_get_attribute(obj: object, attr_name: str) -> tuple[object, bool] | None:
    get_attribute = getattr(obj, "get_attribute", None)
    if not callable(get_attribute):
        return None
    typed_get_attribute = cast("Callable[[str], tuple[object, bool]]", get_attribute)
    value, found = typed_get_attribute(attr_name)
    return value, bool(found)


def modeled_object_has_dynamic_attribute_hook(obj: object) -> bool:
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    get_method = getattr(modeled_class, "get_method", None)
    if not callable(get_method):
        return False
    return get_method("__getattr__") is not None or get_method("__getattribute__") is not None


def literal_string_value(value: StackValue) -> str | None:
    """Extract a concrete string from raw or symbolic string values."""
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString):
        try:
            if not z3.is_string_value(value.z3_str):
                return None
            return value.z3_str.as_string()
        except (AttributeError, z3.Z3Exception):
            return None
    return None
