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

"""Attribute support evidence for ``AttributeError`` detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.havoc import is_havoc
from pysymex._internal.core.types.scalars.path_strings import (
    PATH_STRING_ATTRIBUTE_NAMES,
    PATH_STRING_PREFIXES,
)
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState

BUILTIN_ATTRS_BY_KIND: dict[str, frozenset[str]] = {
    "int": frozenset(dir(int)),
    "float": frozenset(dir(float)),
    "bool": frozenset(dir(bool)),
    "str": frozenset(dir(str)),
    "list": frozenset(dir(list)),
    "dict": frozenset(dir(dict)),
    "tuple": frozenset(dir(tuple)),
    "set": frozenset(dir(set)),
    "bytes": frozenset(dir(bytes)),
    "bytearray": frozenset(dir(bytearray)),
}

_SYMBOLIC_TYPE_CONDITIONS: tuple[tuple[str, str], ...] = (
    ("int", "is_int"),
    ("float", "is_float"),
    ("bool", "is_bool"),
    ("str", "is_str"),
    ("list", "is_list"),
    ("dict", "is_dict"),
)


def resolve_attr_name(raw_attr: object) -> str:
    """Convert bytecode argval to an attribute-name string."""
    if isinstance(raw_attr, str):
        return raw_attr
    if raw_attr is None:
        return ""
    return str(raw_attr)


def collect_invalid_attr_conditions(
    obj: SymbolicValue,
    attr_name: str,
) -> list[z3.BoolRef]:
    """Collect satisfiable primitive-type conditions where ``attr_name`` is invalid."""
    invalid_conditions: list[z3.BoolRef] = []
    for type_name, flag_name in _SYMBOLIC_TYPE_CONDITIONS:
        if attr_name in BUILTIN_ATTRS_BY_KIND[type_name]:
            continue
        if _is_known_symbolic_primitive(obj, type_name, flag_name):
            invalid_conditions.append(getattr(obj, flag_name))
    return invalid_conditions


def has_attribute_in_concrete_types(obj: object, attr_name: str) -> bool:
    """Return whether any concrete runtime type of ``obj`` supports ``attr_name``."""
    candidate_types: Sequence[type[object]] = (
        int,
        float,
        bool,
        str,
        list,
        dict,
        tuple,
        set,
        bytes,
        bytearray,
    )
    for concrete_type in candidate_types:
        if isinstance(obj, concrete_type):
            return attr_name in BUILTIN_ATTRS_BY_KIND[concrete_type.__name__]
    try:
        return hasattr(obj, attr_name)
    except Exception:
        return True


def attribute_access_is_supported(obj: object, attr_name: str, state: VMState) -> bool:
    """Return whether broad skip rules prove this attribute access is supported."""
    if is_havoc(obj):
        return True
    if is_modeled_exception_attribute(obj, attr_name):
        return True
    if is_modeled_symbolic_path_attr(obj, attr_name):
        return True
    if is_abstract_generator_attr(obj, attr_name):
        return True
    container_kind = symbolic_container_kind(obj, state)
    return container_kind is not None and attr_name in BUILTIN_ATTRS_BY_KIND[container_kind]


def is_modeled_exception_attribute(obj: object, attr_name: str) -> bool:
    """Return whether a retained symbolic exception exposes ``attr_name``."""
    payload = _symbolic_exception_payload(obj)
    if payload is None:
        return False
    if attr_name == "args":
        return True
    if attr_name == "value" and payload.type_name == "StopIteration":
        return True
    return attr_name == "exceptions" and _is_exception_group_type(payload.exc_type)


def _symbolic_exception_payload(obj: object) -> SymbolicException | None:
    """Extract a direct or modeled symbolic exception payload."""
    if isinstance(obj, SymbolicException):
        return obj
    if isinstance(obj, SymbolicValue):
        modeled_object = getattr(obj, "_modeled_object", None)
        if isinstance(modeled_object, SymbolicException):
            return modeled_object
    return None


def _is_exception_group_type(exc_type: object) -> bool:
    """Return whether *exc_type* is a concrete exception-group class."""
    return isinstance(exc_type, type) and issubclass(exc_type, BaseExceptionGroup)


def symbolic_container_kind(obj: object, state: VMState) -> str | None:
    """Resolve symbolic container wrappers to their Python container kind."""
    if isinstance(obj, SymbolicString):
        return "str"
    if isinstance(obj, SymbolicBytes):
        return "bytes"
    if isinstance(obj, SymbolicList):
        return _symbolic_list_kind(obj)
    if isinstance(obj, SymbolicDict):
        return "dict"
    if isinstance(obj, SymbolicObject):
        obj_state = state.memory.get(obj.address)
        if isinstance(obj_state, SymbolicList):
            return _symbolic_list_kind(obj_state)
        if isinstance(obj_state, SymbolicDict):
            return "dict"
    if isinstance(obj, SymbolicValue):
        modeled_object = getattr(obj, "_modeled_object", None)
        if isinstance(modeled_object, SymbolicList):
            return _symbolic_list_kind(modeled_object)
        if obj.affinity_type in BUILTIN_ATTRS_BY_KIND:
            return obj.affinity_type
        if obj.runtime_type in BUILTIN_ATTRS_BY_KIND:
            return obj.runtime_type
    return None


def is_modeled_symbolic_path_attr(obj: object, attr_name: str) -> bool:
    """Return whether a supported path-like synthetic attribute is present."""
    return (
        isinstance(obj, SymbolicString)
        and attr_name in PATH_STRING_ATTRIBUTE_NAMES
        and obj.name.startswith(PATH_STRING_PREFIXES)
    )


def is_abstract_generator_attr(obj: object, attr_name: str) -> bool:
    """Return whether an opaque generator is guaranteed to expose an attribute."""
    return (
        isinstance(obj, SymbolicIterator)
        and obj.is_generator
        and attr_name in {"__iter__", "__next__", "close", "send", "throw"}
    )


def _is_known_symbolic_primitive(obj: SymbolicValue, kind: str, flag: str) -> bool:
    """Return True when ``SymbolicValue`` is known to include the primitive kind."""
    if obj.affinity_type == kind:
        return True
    flag_value = getattr(obj, flag)
    return z3.is_true(flag_value)


def _symbolic_list_kind(obj: SymbolicList) -> str:
    type_marker = getattr(obj, "_type", None)
    if isinstance(type_marker, str) and type_marker in BUILTIN_ATTRS_BY_KIND:
        return type_marker
    return "list"
