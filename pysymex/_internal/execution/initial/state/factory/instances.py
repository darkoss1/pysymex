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

"""Modeled-class symbolic instance creation for initial inputs."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.execution.initial.state.types import SymbolicCreatedValue


def create_symbolic_instance_for_class(
    name: str,
    class_name: str,
    init_type_hints: dict[str, str],
    initial_globals: Mapping[str, object] | None,
) -> tuple[SymbolicCreatedValue, z3.BoolRef] | None:
    """Instantiate a modeled class from globals when registry metadata is available."""
    if not initial_globals:
        return None
    class_obj = initial_globals.get(class_name)
    if not isinstance(class_obj, SymbolicValue):
        return None
    class_body = getattr(class_obj, "_modeled_object", None)
    class_init_hints = getattr(class_obj, "_pysymex_init_type_hints", None)
    if isinstance(class_init_hints, dict):
        typed_init_hints = cast("dict[object, object]", class_init_hints)
        for key, value in typed_init_hints.items():
            if isinstance(key, str) and isinstance(value, str):
                init_type_hints.setdefault(key, value.lower())
    try:
        from pysymex._internal.core.classes.registry import class_registry
        from pysymex._internal.execution.opcodes.common.functions.classes.init import (
            apply_straight_line_init_assignments,
        )
        from pysymex._internal.execution.opcodes.common.functions.classes.registration import (
            modeled_class_from_value,
        )

        modeled_cls = None
        if isinstance(class_body, types.CodeType):
            modeled_cls = modeled_class_from_value(class_obj)
        if modeled_cls is None:
            modeled_cls = class_registry.get_class(class_name)
        if modeled_cls is None:
            return None
        for param in getattr(modeled_cls, "init_params", []):
            param_name = getattr(param, "name", None)
            if isinstance(param_name, str) and param_name in init_type_hints:
                param.type_hint = init_type_hints[param_name]

        instance = class_registry.instantiate(modeled_cls)
        apply_straight_line_init_assignments(modeled_cls, instance, [], {})
    except (ImportError, AttributeError, TypeError, ValueError, z3.Z3Exception):
        return None

    result = SymbolicValue(
        _name=name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_obj=Z3_TRUE,
        is_none=Z3_FALSE,
        is_path=Z3_FALSE,
        affinity_type=class_name,
    )
    result.attach_modeled_object(instance)
    return cast("SymbolicCreatedValue", result), Z3_TRUE
