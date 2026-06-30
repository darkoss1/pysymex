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

"""Modeled object attribute facts for ``AttributeError`` detection."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable


def has_dynamic_attribute_hook(obj: object) -> bool:
    """Return whether modeled ``__getattr__`` or ``__getattribute__`` owns lookup."""
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    get_method = getattr(modeled_class, "get_method", None)
    if not callable(get_method):
        return False
    return get_method("__getattr__") is not None or get_method("__getattribute__") is not None


def modeled_object_has_attribute(obj: object, attr_name: str) -> bool | None:
    """Return True/False if the modeled MRO declares ``attr_name``, None if unknown."""
    modeled_class = getattr(obj, "cls", None)
    for candidate in getattr(modeled_class, "mro", ()):
        bindings = getattr(candidate, "_pysymex_declared_descriptors", None)
        if isinstance(bindings, dict) and attr_name in bindings:
            return True
    get_attribute = cast(
        "Callable[[str], tuple[object, bool]] | None",
        getattr(obj, "get_attribute", None),
    )
    if not callable(get_attribute):
        return None
    _, found = get_attribute(attr_name)
    return bool(found)


def modeled_object_can_store_attr(obj: object, attr_name: str) -> bool:
    """Return whether ``attr_name`` can be written on the modeled object."""
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    get_method = getattr(modeled_class, "get_method", None)
    if callable(get_method) and get_method("__setattr__") is not None:
        return True
    properties_obj = getattr(modeled_class, "properties", {})
    if isinstance(properties_obj, dict) and attr_name in properties_obj:
        properties = cast("dict[str, object]", properties_obj)
        prop = properties[attr_name]
        return getattr(prop, "fset", None) is not None
    slots = getattr(modeled_class, "slots", None)
    return slots is None or attr_name in slots


def modeled_object_can_delete_attr(obj: object) -> bool:
    """Return whether modeled ``__delattr__`` owns delete semantics."""
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    get_method = getattr(modeled_class, "get_method", None)
    return callable(get_method) and get_method("__delattr__") is not None


def modeled_object_has_readonly_prop(obj: object, attr_name: str) -> bool:
    """Return whether ``attr_name`` is a read-only property on the modeled object."""
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    properties_obj = getattr(modeled_class, "properties", {})
    if not isinstance(properties_obj, dict) or attr_name not in properties_obj:
        return False
    properties = cast("dict[str, object]", properties_obj)
    return getattr(properties[attr_name], "fset", None) is None
