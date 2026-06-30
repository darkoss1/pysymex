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

"""Modeled ``object.__new__`` allocation for class-call dispatch."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def try_modeled_object_allocation(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Allocate a known modeled class through ``object.__new__(cls)``."""
    if func_obj is not object.__new__ or len(args) != 1 or kwargs:
        return None
    target = args[0]
    from pysymex._internal.core.classes.registry import class_registry
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.values import (
        modeled_instance_value,
    )
    from pysymex._internal.execution.opcodes.common.functions.classes.registration import (
        modeled_class_from_python_type,
        modeled_class_from_value,
    )

    if isinstance(target, SymbolicValue):
        modeled_cls = modeled_class_from_value(target)
    elif isinstance(target, type):
        modeled_cls = modeled_class_from_python_type(target)
    else:
        return None

    if modeled_cls is None:
        return None
    instance = class_registry.create_instance(modeled_cls)
    state = state.push(modeled_instance_value(modeled_cls.name, instance, state.pc))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
