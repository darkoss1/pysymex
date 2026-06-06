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

"""Shared call-resolution helpers, summary-cache protocols, and call guards.

Used by CALL opcode lowering, model dispatch, and interprocedural dispatch. This module
does not register opcode handlers or own CPython stack effects.
"""

from __future__ import annotations

from collections.abc import Iterable
import re
from typing import TYPE_CHECKING, Protocol, TypeGuard, cast

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_int_val, get_real_val, get_string_val
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.containers.sequences import SymbolicTuple
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.havoc import HavocValue
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue


UNMODELED_CALL_ABSTRACTION = "unmodeled_call_abstraction"
UNSUPPORTED_CALL_PROTOCOL = "unsupported_call_protocol"
_MAX_HAVOC_CALL_TOKEN_LENGTH = 80


def _sanitize_havoc_call_token(raw: object) -> str:
    """Return a bounded Z3-symbol token for unmodeled-call provenance."""
    token = re.sub(r"[^0-9A-Za-z_]+", "_", str(raw)).strip("_")
    if not token:
        return "callable"
    if len(token) <= _MAX_HAVOC_CALL_TOKEN_LENGTH:
        return token
    prefix_length = _MAX_HAVOC_CALL_TOKEN_LENGTH // 2
    suffix_length = _MAX_HAVOC_CALL_TOKEN_LENGTH - prefix_length - 1
    return f"{token[:prefix_length]}_{token[-suffix_length:]}"


def _callable_havoc_token(func_obj: object) -> str:
    """Return the best stable callable identifier available for diagnostics."""
    for attr_name in ("model_name", "__qualname__", "__name__", "_func_name", "name"):
        candidate = getattr(func_obj, attr_name, None)
        if isinstance(candidate, str) and candidate:
            return _sanitize_havoc_call_token(candidate)
    return _sanitize_havoc_call_token(type(func_obj).__name__)


def create_unmodeled_call_havoc(
    state: VMState,
    func_obj: object,
) -> tuple[HavocValue, z3.BoolRef]:
    """Create an unmodeled-call result while preserving callable provenance."""
    return HavocValue.havoc(f"havoc_call_{_callable_havoc_token(func_obj)}@{state.pc}")


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


class SummaryCacheProtocol(Protocol):
    """Protocol for cross-function summary cache."""

    def get(
        self,
        name: str,
        args: list[StackValue],
        constraints: list[z3.BoolRef],
    ) -> object:
        """Look up a cached summary for *name* at *args* under *constraints*."""
        ...


class CrossFunctionProtocol(Protocol):
    """Protocol for cross-function analyzer objects."""

    function_summary_cache: SummaryCacheProtocol


class ObjectMapProtocol(Protocol):
    """Mapping-like runtime protocol used for strict key/value narrowing."""

    def __contains__(self, key: object, /) -> bool:
        """Return whether *key* is present in the mapping."""
        ...

    def __getitem__(self, key: object, /) -> object:
        """Return the value stored under *key*."""
        ...

    def __setitem__(self, key: object, value: object, /) -> None:
        """Store *value* under *key* in the mapping."""
        ...

    def items(self) -> Iterable[tuple[object, object]]:
        """Iterate key/value pairs for strict mapping narrowing."""
        ...


def is_object_map(value: object) -> TypeGuard[ObjectMapProtocol]:
    """Return ``True`` when *value* behaves like a mutable mapping."""
    return (
        hasattr(value, "items")
        and callable(getattr(value, "items", None))
        and hasattr(value, "__contains__")
        and hasattr(value, "__getitem__")
        and hasattr(value, "__setitem__")
    )


def is_symbolic_module_receiver(value: object, state: VMState) -> bool:
    """Return whether a call receiver is a symbolic imported module object."""
    if not isinstance(value, SymbolicObject) or value.address == -1:
        return False
    heap_value = state.load_heap(value.address)
    return is_object_map(heap_value) and "__module_name__" in heap_value


def to_z3_expr(value: StackValue) -> z3.ExprRef | None:
    """Best-effort conversion from stack values to Z3 expressions."""
    if isinstance(value, SymbolicValue):
        return value.to_z3()
    if isinstance(value, int) and not isinstance(value, bool):
        return get_int_val(value)
    if isinstance(value, bool):
        return Z3_TRUE if value else Z3_FALSE
    if isinstance(value, float):
        return get_real_val(value)
    if isinstance(value, str):
        return get_string_val(value)
    return None


def as_mapping(value: object) -> dict[str, object] | None:
    """Return a concrete ``dict[str, object]`` for mapping-like values."""
    if is_object_map(value):
        return {k: v for k, v in value.items() if isinstance(k, str)}
    return None


def as_stack_value(value: object) -> StackValue:
    """Best-effort conversion into the StackValue domain used by VMState."""
    if value is None:
        return None
    try:
        from pysymex.models.objects import SymbolicMethod
    except ImportError:
        SymbolicMethod = None
    if SymbolicMethod is not None and isinstance(value, SymbolicMethod):
        return cast("StackValue", value)
    if isinstance(
        value,
        (
            SymbolicValue,
            SymbolicNone,
            SymbolicString,
            SymbolicList,
            SymbolicDict,
            SymbolicObject,
            SymbolicType,
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


def bind_heap_modeled_method(value: object, receiver: StackValue) -> object:
    """Bind unbound modeled methods to the current call receiver when needed."""
    try:
        from pysymex.models.objects import SymbolicMethod
    except ImportError:
        return value
    if isinstance(value, SymbolicMethod) and not value.is_bound:
        return value.bind_to_instance(receiver)
    return value


def map_get(value: ObjectMapProtocol, key: str) -> tuple[bool, object | None]:
    """Read a mapping entry while preserving existence vs None values."""
    if key in value:
        return True, value[key]
    return False, None


def map_set(value: ObjectMapProtocol, key: str, item: StackValue) -> None:
    """Store a value in a mapping-like object."""
    value[key] = item


def map_to_stack_dict(value: ObjectMapProtocol) -> dict[str, StackValue]:
    """Convert a mutable mapping-like object to ``dict[str, StackValue]``."""
    return {k: as_stack_value(v) for k, v in value.items() if isinstance(k, str)}


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
