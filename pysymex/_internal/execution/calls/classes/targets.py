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

"""Modeled class target identification and registry resolution."""

from __future__ import annotations

import types

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.classes.protocols import apply_init_type_hints


def class_target_name(func_obj: object) -> str | None:
    """Return the user-visible class target name for a potential constructor call."""
    name = (
        getattr(func_obj, "_name", None)
        or getattr(func_obj, "name", None)
        or (func_obj.__name__ if isinstance(func_obj, type) else None)
    )
    return name if isinstance(name, str) else None


def is_class_like_target(func_obj: object) -> bool:
    """Return whether a call target may represent a Python or symbolic class."""
    if isinstance(func_obj, type):
        return True
    return (
        isinstance(func_obj, SymbolicValue) and getattr(func_obj, "affinity_type", None) == "type"
    )


def class_target_code(func_obj: object) -> types.CodeType | None:
    """Return the code object used to register a modeled class, when available."""
    func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)
    if func_code is None and isinstance(func_obj, type):
        init_func = getattr(func_obj, "__init__", None)
        if init_func and hasattr(init_func, "__code__"):
            func_code = init_func.__code__

    if func_code is None:
        modeled_code = getattr(func_obj, "_modeled_object", None)
        if isinstance(modeled_code, types.CodeType):
            func_code = modeled_code

    return func_code if isinstance(func_code, types.CodeType) else None


def resolve_modeled_class(
    func_obj: object,
    class_name: str,
    func_code: types.CodeType | None,
    init_type_hints: object,
):
    """Resolve or register the modeled class backing one constructor call target."""
    from pysymex._internal.core.classes.classes import SymbolicClass
    from pysymex._internal.core.classes.registry import class_registry, extract_init_params
    from pysymex._internal.execution.calls.classes.stdlib import (
        concrete_named_tuple_fields,
        configure_concrete_named_tuple_class,
    )
    from pysymex._internal.execution.opcodes.common.functions.classes.descriptors.methods import (
        register_class_body_methods,
    )
    from pysymex._internal.execution.opcodes.common.functions.classes.registration import (
        modeled_class_from_python_type,
        modeled_class_from_value,
    )

    modeled_cls = None
    if isinstance(func_obj, SymbolicValue):
        modeled_cls = modeled_class_from_value(func_obj)

    concrete_fields = concrete_named_tuple_fields(func_obj)
    if concrete_fields is not None:
        modeled_cls = class_registry.register_class(SymbolicClass(class_name))
        configure_concrete_named_tuple_class(modeled_cls, concrete_fields)
    elif modeled_cls is None and isinstance(func_obj, type):
        modeled_cls = modeled_class_from_python_type(func_obj)
        if func_code is not None and class_registry.get_by_code_object(func_code) is None:
            class_registry.register_code_object(func_code, modeled_cls)
    elif modeled_cls is None and func_code is not None:
        modeled_cls = class_registry.get_by_code_object(func_code)
        if modeled_cls is None:
            modeled_cls = class_registry.register_class(SymbolicClass(class_name))
            class_registry.register_code_object(func_code, modeled_cls)
            register_class_body_methods(
                modeled_cls,
                func_obj if isinstance(func_obj, type) else func_code,
            )
            apply_init_type_hints(modeled_cls, init_type_hints)
            if not modeled_cls.init_params and getattr(func_code, "co_name", "") != class_name:
                params = extract_init_params(func_code)
                if params:
                    modeled_cls.set_init_params(params)
                    apply_init_type_hints(modeled_cls, init_type_hints)
    else:
        modeled_cls = class_registry.get_class(class_name)

    return modeled_cls
