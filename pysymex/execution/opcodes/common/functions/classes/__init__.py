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

"""Class body registration, ``__init__``, slots, and instance copy helpers for calls.

Aggregates :mod:`pysymex.execution.opcodes.common.functions.classes` submodules used when
bytecode constructs or mutates modeled local classes (not stdlib types registered elsewhere).
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING

from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex.core.state.types import is_bound
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.functions.classes.descriptor.assignments import (
    class_body_descriptor_assignments,
)
from pysymex.execution.opcodes.common.functions.classes.descriptors import (
    class_level_modeled_attribute as class_level_modeled_attribute,
    register_class_body_methods as register_class_body_methods,
)
from pysymex.execution.opcodes.common.functions.classes.init import (
    apply_straight_line_init_assignments as apply_straight_line_init_assignments,
)
from pysymex.execution.opcodes.common.functions.classes.instances import (
    copy_symbolic_value_with_modeled_object as copy_symbolic_value_with_modeled_object,
    modeled_instance_value as modeled_instance_value,
    propagate_container_mutation_reference as propagate_container_mutation_reference,
    propagate_list_mutation_reference as propagate_list_mutation_reference,
    replace_identity_references as replace_identity_references,
)
from pysymex.execution.opcodes.common.functions.classes.registration import (
    modeled_class_from_python_type as modeled_class_from_python_type,
    modeled_class_from_value as modeled_class_from_value,
)
from pysymex.execution.calls.payload import function_payload
from pysymex.execution.calls.helpers import concrete_string

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def apply_build_class_model(
    state: VMState,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
) -> OpcodeResult | None:
    """Model CPython ``__build_class__`` without executing class-body side effects."""
    kwargs = kwargs or {}
    if len(args) < 2:
        return None
    body_func = args[0]
    class_name = concrete_string(args[1])
    if class_name is None:
        class_name = getattr(body_func, "_name", None) or getattr(body_func, "name", None)
    if not isinstance(class_name, str) or not class_name:
        class_name = f"class_{state.pc}"

    code_obj = getattr(body_func, "_modeled_object", None)
    payload = function_payload(code_obj)
    class_val = SymbolicValue(
        _name=class_name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_obj=Z3_TRUE,
        is_none=Z3_FALSE,
        is_path=Z3_FALSE,
        affinity_type="type",
    )
    if payload is not None:
        class_val.attach_modeled_object(payload)
        closure_by_name = _payload_closure_by_name(state, payload)
        descriptor_assignments = class_body_descriptor_assignments(
            payload.code,
            lambda name: _lookup_class_body_name(state, name, closure_by_name),
        )
        if descriptor_assignments:
            setattr(class_val, "_pysymex_descriptor_assignments", descriptor_assignments)
    elif isinstance(code_obj, types.CodeType):
        class_val.attach_modeled_object(code_obj)
        descriptor_assignments = class_body_descriptor_assignments(
            code_obj,
            lambda name: _lookup_class_body_name(state, name),
        )
        if descriptor_assignments:
            setattr(class_val, "_pysymex_descriptor_assignments", descriptor_assignments)
    import functools

    if state.global_vars.get("functools") is functools:
        setattr(class_val, "_pysymex_trusted_cached_property", True)
    base_values = tuple(args[2:])
    metaclass_value = kwargs.get("metaclass")
    if isinstance(metaclass_value, SymbolicValue):
        setattr(class_val, "_pysymex_metaclass_value", metaclass_value)
    setattr(class_val, "_pysymex_base_values", base_values)
    if not base_values and not kwargs:
        setattr(class_val, "_pysymex_plain_class_definition", True)
    setattr(
        class_val,
        "_pysymex_bases_complete",
        all(isinstance(base, (SymbolicValue, type)) for base in base_values),
    )
    state = state.push(class_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _payload_closure_by_name(state: VMState, payload: object) -> dict[str, object]:
    """Return function payload closure entries keyed by free-variable name."""
    resolved = function_payload(payload)
    if resolved is None or not resolved.closure:
        return {}
    return {
        name: _dereference_cell(state, cell)
        for name, cell in zip(resolved.code.co_freevars, resolved.closure, strict=False)
    }


def _lookup_class_body_name(
    state: VMState,
    name: str,
    closure_by_name: dict[str, object] | None = None,
) -> object | None:
    """Resolve a name visible to a class body without executing the body."""
    if closure_by_name is not None and name in closure_by_name:
        return closure_by_name[name]
    local_value = state.get_local(name)
    if is_bound(local_value) and local_value is not None:
        return _dereference_cell(state, local_value)
    return state.get_global(name)


def _dereference_cell(state: VMState, value: object) -> object | None:
    """Return a cell object's current heap value, or *value* when it is not a cell."""
    if isinstance(value, SymbolicObject) and value.name.startswith("cell_"):
        return state.load_heap(value.address)
    return value
