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

"""Runtime descriptor retention for modeled class attribute writes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.functions.classes.descriptor.bindings import (
    DescriptorBinding,
)

if TYPE_CHECKING:
    from pysymex._internal.core.classes.classes import SymbolicClass


def register_dynamic_binding(
    modeled_cls: SymbolicClass,
    owner_value: SymbolicValue,
    attr_name: str,
    descriptor: object,
) -> bool:
    """Retain a descriptor instance assigned to a modeled class at runtime."""
    if not isinstance(descriptor, SymbolicValue):
        return False

    from pysymex._internal.core.classes.instances import SymbolicInstance

    descriptor_instance = getattr(descriptor, "_modeled_object", None)
    if not isinstance(descriptor_instance, SymbolicInstance):
        return False

    descriptor_cls = descriptor_instance.cls
    get_method = descriptor_cls.lookup_method("__get__")
    set_method = descriptor_cls.lookup_method("__set__")
    delete_method = descriptor_cls.lookup_method("__delete__")
    if get_method is None and set_method is None and delete_method is None:
        return False

    bindings = modeled_cls.declared_descriptors
    retained = dict(bindings) if bindings is not None else {}
    retained[attr_name] = DescriptorBinding(
        descriptor=descriptor,
        owner=owner_value,
        is_data=set_method is not None or delete_method is not None,
        has_getter=get_method is not None,
    )
    modeled_cls.set_declared_descriptors(retained)
    modeled_cls.class_attrs.pop(attr_name, None)
    modeled_cls.class_vars.pop(attr_name, None)
    return True
