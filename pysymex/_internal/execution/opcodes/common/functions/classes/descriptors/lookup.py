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

"""Symbolic class-level method and class-variable lookup."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.values import SymbolicValue


def modeled_class_from_symbolic_class_value(obj: SymbolicValue) -> object | None:
    """Resolve a modeled class registry entry from a symbolic type value."""
    from pysymex._internal.execution.opcodes.common.functions.classes.registration import (
        modeled_class_from_value,
    )

    return modeled_class_from_value(obj)


def class_level_modeled_attribute(obj: SymbolicValue, attr_name: str) -> tuple[object, bool]:
    """Look up class methods or class variables on a symbolic type operand."""
    modeled_cls = modeled_class_from_symbolic_class_value(obj)
    if modeled_cls is None:
        return None, False
    get_method = getattr(modeled_cls, "get_method", None)
    if callable(get_method):
        method = get_method(attr_name)
        if method is not None:
            method_type = getattr(method, "method_type", None)
            if getattr(method_type, "name", "") == "CLASS":
                bind_to_class = getattr(method, "bind_to_class", None)
                if callable(bind_to_class):
                    return bind_to_class(obj), True
            return method, True
    class_vars = getattr(modeled_cls, "class_vars", {})
    if isinstance(class_vars, dict) and attr_name in class_vars:
        typed_class_vars = cast("dict[str, object]", class_vars)
        return typed_class_vars[attr_name], True
    return None, False
