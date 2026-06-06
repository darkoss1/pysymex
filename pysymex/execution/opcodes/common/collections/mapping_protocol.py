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

"""Modeled mapping-protocol extraction for dict unpack opcodes.

Recognizes simple wrapper objects whose ``keys`` and ``__getitem__`` methods both
delegate to the same retained mapping attribute. This gives ``DICT_UPDATE`` and
``DICT_MERGE`` CPython-compatible precision without executing arbitrary user hooks.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, cast

from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.opcodes.common.collections.static_mapping_patterns import (
    NO_CONSTANT_RETURN,
    constant_return_value,
    getitem_method_backing_attr,
    keys_method_backing_attr,
    method_code,
    static_item_mapping,
)

if TYPE_CHECKING:
    from pysymex.models.objects import SymbolicInstance


UNSUPPORTED_MAPPING_PROTOCOL = "unsupported_mapping_protocol"


def extract_modeled_instance_mapping(value: object) -> SymbolicDict | dict[object, object] | None:
    """Return a retained mapping from a simple modeled wrapper instance."""
    modeled = _modeled_instance(value)
    if modeled is None:
        return None
    keys_type_error = _modeled_keys_non_iterable_type_error(modeled)
    if keys_type_error is not None:
        raise TypeError(keys_type_error)
    constant_mapping = _constant_keys_static_item_mapping(modeled)
    if constant_mapping is not None:
        return constant_mapping
    attr_name = _mapping_backing_attr(modeled)
    if attr_name is None:
        return None
    if attr_name not in modeled.attrs:
        return None
    return _retained_mapping(modeled.attrs[attr_name])


def definite_modeled_non_mapping_type_name(value: object) -> str | None:
    """Return the modeled class name when ``keys`` lookup is definitely absent."""
    modeled = _modeled_instance(value)
    if modeled is None:
        return None
    if _has_dynamic_attribute_lookup(modeled) or _has_possible_keys_lookup(modeled):
        return None
    cls = getattr(modeled, "cls", None)
    name = getattr(cls, "name", None)
    return name if isinstance(name, str) and name else None


def modeled_mapping_protocol_is_inconclusive(value: object) -> bool:
    """Return whether modeled mapping dispatch may exist but was not extracted."""
    modeled = _modeled_instance(value)
    if modeled is None:
        return False
    if _has_dynamic_attribute_lookup(modeled):
        return True
    return _has_possible_keys_lookup(modeled)


def _modeled_instance(value: object) -> SymbolicInstance | None:
    """Return the attached modeled instance for a symbolic object value."""
    if not isinstance(value, SymbolicValue):
        return None

    try:
        from pysymex.models.objects import SymbolicInstance as RuntimeSymbolicInstance
    except ImportError:
        return None

    modeled = getattr(value, "_modeled_object", None)
    return modeled if isinstance(modeled, RuntimeSymbolicInstance) else None


def _retained_mapping(value: object) -> SymbolicDict | dict[object, object] | None:
    """Return the concrete or symbolic mapping retained by an instance attribute."""
    if isinstance(value, SymbolicDict):
        return value
    if isinstance(value, Mapping):
        return dict(cast("Mapping[object, object]", value))
    if isinstance(value, SymbolicValue):
        const_value = value.value
        if isinstance(const_value, Mapping):
            return dict(cast("Mapping[object, object]", const_value))
        modeled_object = getattr(value, "_modeled_object", None)
        if isinstance(modeled_object, SymbolicDict):
            return modeled_object
    return None


def _mapping_backing_attr(instance: object) -> str | None:
    """Return the shared backing attribute for simple mapping protocol methods."""
    cls = getattr(instance, "cls", None)
    get_method = getattr(cls, "get_method", None)
    if not callable(get_method):
        return None
    if _has_dynamic_attribute_lookup(instance):
        return None

    keys_attr = keys_method_backing_attr(method_code(get_method("keys")))
    getitem_attr = getitem_method_backing_attr(method_code(get_method("__getitem__")))
    if keys_attr is None or keys_attr != getitem_attr:
        return None
    properties = getattr(cls, "properties", None)
    if isinstance(properties, dict) and keys_attr in properties:
        return None
    return keys_attr


def _has_dynamic_attribute_lookup(instance: object) -> bool:
    """Return whether attribute lookup can be affected by modeled dynamic hooks."""
    cls = getattr(instance, "cls", None)
    get_method = getattr(cls, "get_method", None)
    if not callable(get_method):
        return True
    return get_method("__getattribute__") is not None or get_method("__getattr__") is not None


def _has_possible_keys_lookup(instance: object) -> bool:
    """Return whether ``obj.keys`` might resolve without dynamic lookup hooks."""
    attrs = getattr(instance, "attrs", None)
    if isinstance(attrs, dict) and "keys" in attrs:
        return True
    cls = getattr(instance, "cls", None)
    properties = getattr(cls, "properties", None)
    if isinstance(properties, dict) and "keys" in properties:
        return True
    get_method = getattr(cls, "get_method", None)
    if callable(get_method) and get_method("keys") is not None:
        return True
    get_attribute = getattr(cls, "get_attribute", None)
    return callable(get_attribute) and get_attribute("keys") is not None


def _modeled_keys_non_iterable_type_error(instance: SymbolicInstance) -> str | None:
    """Return CPython's ``keys()`` non-iterable error for a constant method body."""
    if _has_dynamic_attribute_lookup(instance):
        return None
    method = instance.cls.get_method("keys")
    constant = constant_return_value(method_code(method))
    if constant is NO_CONSTANT_RETURN:
        return None
    try:
        iter(cast("Iterable[object]", constant))
    except TypeError:
        return (
            f"{instance.cls.name}.keys() returned a non-iterable (type {type(constant).__name__})"
        )
    return None


def _constant_keys_static_item_mapping(instance: SymbolicInstance) -> dict[object, object] | None:
    """Extract mapping data from constant ``keys`` and static ``__getitem__`` bodies."""
    if _has_dynamic_attribute_lookup(instance):
        return None
    return static_item_mapping(
        method_code(instance.cls.get_method("keys")),
        method_code(instance.cls.get_method("__getitem__")),
    )


__all__ = [
    "UNSUPPORTED_MAPPING_PROTOCOL",
    "definite_modeled_non_mapping_type_name",
    "extract_modeled_instance_mapping",
    "modeled_mapping_protocol_is_inconclusive",
]
