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

"""Modeled instance value construction and copy helpers."""

from __future__ import annotations

import copy

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.scalars.values import SymbolicValue


def _clone_modeled_object(value: object) -> object | None:
    """Return a copy of a modeled instance when the object layer supports it."""
    try:
        from pysymex._internal.core.classes.instances import SymbolicInstance
    except ImportError:
        return None
    if not isinstance(value, SymbolicInstance):
        return None
    return value.copy()


def copy_symbolic_value_with_modeled_object(obj: SymbolicValue) -> SymbolicValue | None:
    """Clone a symbolic value and its attached modeled object together."""
    cloned_model = _clone_modeled_object(getattr(obj, "_modeled_object", None))
    if cloned_model is None:
        return None
    cloned_obj = copy.copy(obj)
    cloned_obj.attach_modeled_object(cloned_model)
    return cloned_obj


def modeled_instance_value(class_name: str, instance: object, pc: int) -> SymbolicValue:
    """Wrap a modeled instance in the value representation used by the VM."""
    result_val = SymbolicValue(
        _name=f"instance_{class_name}_{pc}",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_obj=Z3_TRUE,
        is_none=Z3_FALSE,
        is_path=Z3_FALSE,
        affinity_type=class_name,
    )
    result_val.attach_modeled_object(instance)
    return result_val
