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

"""Register members from already-created concrete Python classes."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.classes.types import MethodType
from pysymex._internal.execution.opcodes.common.functions.classes.descriptor.properties import (
    property_marker_deleter,
    property_marker_getter,
    property_marker_setter,
)

if TYPE_CHECKING:
    from pysymex._internal.core.classes.classes import SymbolicClass


def register_concrete_type_members(modeled_cls: SymbolicClass, class_body: type) -> None:
    """Populate modeled members from a concrete Python ``type`` without executing hooks."""
    for name, member in class_body.__dict__.items():
        if isinstance(member, property):
            modeled_cls.add_property(
                name,
                fget=property_marker_getter if member.fget is not None else None,
                fset=property_marker_setter if member.fset is not None else None,
                fdel=property_marker_deleter if member.fdel is not None else None,
                getter_code=getattr(member.fget, "__code__", None),
                setter_code=getattr(member.fset, "__code__", None),
                deleter_code=getattr(member.fdel, "__code__", None),
                getter_func=member.fget,
                setter_func=member.fset,
                deleter_func=member.fdel,
            )
        elif isinstance(member, (types.FunctionType, types.MethodType)):
            func_code = getattr(member, "__code__", None)
            if func_code:
                modeled_cls.add_method(
                    name,
                    member,
                    method_type=MethodType.INSTANCE,
                    parameters=list(func_code.co_varnames[: func_code.co_argcount]),
                )
        elif isinstance(member, classmethod):
            func = getattr(cast("object", member), "__func__", None)
            func_code = getattr(func, "__code__", None) if func else None
            if func_code and callable(func):
                modeled_cls.add_method(
                    name,
                    func,
                    method_type=MethodType.CLASS,
                    parameters=list(func_code.co_varnames[: func_code.co_argcount]),
                )
        elif isinstance(member, staticmethod):
            func = getattr(cast("object", member), "__func__", None)
            func_code = getattr(func, "__code__", None) if func else None
            if func_code and callable(func):
                modeled_cls.add_method(
                    name,
                    func,
                    method_type=MethodType.STATIC,
                    parameters=list(func_code.co_varnames[: func_code.co_argcount]),
                )
