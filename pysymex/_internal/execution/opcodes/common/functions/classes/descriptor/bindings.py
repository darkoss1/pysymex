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

"""Parse and retain descriptor assignments from modeled class body bytecode.

Builds :class:`DeclaredDescriptorBinding` records (owner, data vs non-data, getter carrier)
while ``MAKE_FUNCTION`` / ``STORE_NAME`` run during class setup. Consumed by attribute load
and ``hasattr`` dispatch modules.

Limitations:
    Only descriptors visible in the analyzed class body are captured; metaclass installs are ignored.
"""

from __future__ import annotations

import types
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.calls.payload import function_payload
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.classes.classes import SymbolicClass


@dataclass(frozen=True, slots=True)
class DescriptorBinding:
    """A declared descriptor assignment and its supported execution carrier."""

    descriptor: SymbolicValue | None
    owner: SymbolicValue
    is_data: bool
    has_getter: bool


def register_declared_bindings(modeled_cls: SymbolicClass, owner_value: SymbolicValue) -> None:
    """Retain zero-argument descriptor instances whose semantics are bounded."""
    assignments = getattr(owner_value, "_pysymex_descriptor_assignments", None)
    if not isinstance(assignments, dict):
        return
    from pysymex._internal.core.classes.registry import class_registry
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.values import (
        modeled_instance_value,
    )
    from pysymex._internal.execution.opcodes.common.functions.classes.registration import (
        modeled_class_from_value,
    )

    retained: dict[str, DescriptorBinding] = {}
    for attr_name, assignment in cast("dict[object, object]", assignments).items():
        parsed_assignment = _descriptor_assignment(assignment)
        if not isinstance(attr_name, str) or parsed_assignment is None:
            continue
        descriptor_value, constructor_args = parsed_assignment
        descriptor_cls = modeled_class_from_value(descriptor_value)
        if descriptor_cls is None:
            continue
        get_method = descriptor_cls.lookup_method("__get__")
        set_method = descriptor_cls.lookup_method("__set__")
        delete_method = descriptor_cls.lookup_method("__delete__")
        init_method = descriptor_cls.lookup_method("__init__")
        set_name_method = descriptor_cls.lookup_method("__set_name__")
        if get_method is None and set_method is None and delete_method is None:
            continue
        synthesized_state = (
            _synthesized_set_name_attributes(set_name_method, attr_name, owner_value)
            if set_name_method is not None
            else {}
        )
        constructor_state = _synthesized_init_attributes(init_method, constructor_args)
        safe = (
            constructor_state is not None
            and synthesized_state is not None
            and all(
                _body_is_bounded(
                    method,
                    method_name,
                    frozenset({**constructor_state, **synthesized_state}),
                )
                for method_name, method in (
                    ("__get__", get_method),
                    ("__set__", set_method),
                    ("__delete__", delete_method),
                )
                if method is not None
            )
        )
        descriptor = None
        if safe and constructor_state is not None and synthesized_state is not None:
            instance = class_registry.create_instance(descriptor_cls)
            if _apply_synthesized_attributes(instance, {**constructor_state, **synthesized_state}):
                descriptor = modeled_instance_value(descriptor_cls.name, instance, -1)
        retained[attr_name] = DescriptorBinding(
            descriptor=descriptor,
            owner=owner_value,
            is_data=set_method is not None or delete_method is not None,
            has_getter=get_method is not None,
        )
    if retained:
        modeled_cls.set_declared_descriptors(retained)


def _descriptor_assignment(value: object) -> tuple[SymbolicValue, tuple[object, ...] | None] | None:
    """Parse a ``(descriptor value, constructor args)`` tuple from class setup."""
    if not isinstance(value, tuple):
        return None
    items = cast("tuple[object, ...]", value)
    if (
        len(items) != 2
        or not isinstance(items[0], SymbolicValue)
        or not (items[1] is None or isinstance(items[1], tuple))
    ):
        return None
    return items[0], cast("tuple[object, ...] | None", items[1])


def find_declared_descriptor_binding(
    receiver: SymbolicValue,
    attr_name: str,
) -> DescriptorBinding | None:
    """Return the first retained descriptor binding along the receiver MRO."""
    from pysymex._internal.core.classes.instances import SymbolicInstance

    instance = getattr(receiver, "_modeled_object", None)
    if not isinstance(instance, SymbolicInstance):
        return None
    return _find_binding_in_mro(instance.cls, attr_name)


def find_declared_class_descriptor_binding(
    receiver: SymbolicValue,
    attr_name: str,
) -> DescriptorBinding | None:
    """Return a retained descriptor binding for symbolic class attribute access."""
    from pysymex._internal.execution.opcodes.common.functions.classes.registration import (
        modeled_class_from_value,
    )

    modeled_cls = modeled_class_from_value(receiver)
    if modeled_cls is None:
        return None
    return _find_binding_in_mro(modeled_cls, attr_name)


def _find_binding_in_mro(modeled_cls: SymbolicClass, attr_name: str) -> DescriptorBinding | None:
    """Return the first retained descriptor binding along a modeled class MRO."""
    for candidate_cls in modeled_cls.mro:
        bindings = getattr(candidate_cls, "_pysymex_declared_descriptors", None)
        if isinstance(bindings, dict) and attr_name in bindings:
            return cast("DescriptorBinding", bindings[attr_name])
    return None


def _synthesized_set_name_attributes(
    method: object,
    attr_name: str,
    owner_value: SymbolicValue,
) -> dict[str, object] | None:
    """Recognize direct name and owner captures from ``__set_name__`` only."""
    code = _method_code(method)
    if code is None:
        return None
    parameters = code.co_varnames[: code.co_argcount]
    if len(parameters) < 3:
        return None
    descriptor_name = parameters[0]
    supported_values: dict[str, object] = {parameters[1]: owner_value, parameters[2]: attr_name}
    return _synthesized_direct_assignments(code, descriptor_name, supported_values)


def _synthesized_init_attributes(
    method: object | None,
    constructor_args: tuple[object, ...] | None,
) -> dict[str, object] | None:
    """Recognize direct initializer parameter captures for literal constructor args."""
    if method is None:
        return {} if constructor_args == () else None
    if not constructor_args:
        return None
    code = _method_code(method)
    if code is None:
        return None
    parameters = code.co_varnames[: code.co_argcount]
    if len(parameters) != len(constructor_args) + 1:
        return None
    supported_values = dict(zip(parameters[1:], constructor_args, strict=True))
    return _synthesized_direct_assignments(code, parameters[0], supported_values)


def _synthesized_direct_assignments(
    code: types.CodeType,
    descriptor_name: str,
    supported_values: dict[str, object],
) -> dict[str, object] | None:
    """Recognize direct ``self.field = parameter`` assignments only."""
    meaningful = [
        instruction
        for instruction in get_instructions(code)
        if instruction.opname not in {"RESUME", "RETURN_CONST", "RETURN_VALUE", "LOAD_CONST"}
    ]
    synthesized: dict[str, object] = {}
    index = 0
    while index < len(meaningful):
        instruction = meaningful[index]
        fast_pair_value: object | None = None
        for parameter, value in supported_values.items():
            if instruction.argval == (parameter, descriptor_name):
                fast_pair_value = value
                break
        if (
            instruction.opname == "LOAD_FAST_LOAD_FAST"
            and fast_pair_value is not None
            and index + 1 < len(meaningful)
            and meaningful[index + 1].opname == "STORE_ATTR"
            and isinstance(meaningful[index + 1].argval, str)
        ):
            synthesized[meaningful[index + 1].argval] = fast_pair_value
            index += 2
            continue
        if (
            instruction.opname == "LOAD_FAST"
            and isinstance(instruction.argval, str)
            and instruction.argval in supported_values
            and index + 2 < len(meaningful)
            and meaningful[index + 1].opname == "LOAD_FAST"
            and meaningful[index + 1].argval == descriptor_name
            and meaningful[index + 2].opname == "STORE_ATTR"
            and isinstance(meaningful[index + 2].argval, str)
        ):
            synthesized[meaningful[index + 2].argval] = supported_values[instruction.argval]
            index += 3
            continue
        return None
    return synthesized


def _apply_synthesized_attributes(instance: object, values: dict[str, object]) -> bool:
    """Apply statically synthesized fields to a modeled descriptor instance."""
    set_attribute = getattr(instance, "set_attribute", None)
    if not callable(set_attribute):
        return False
    return all(set_attribute(name, value) for name, value in values.items())


def _body_is_bounded(
    method: object,
    method_name: str,
    synthesized_attributes: frozenset[str],
) -> bool:
    """Return whether a descriptor body avoids unknown descriptor-instance state."""
    code = _method_code(method)
    if code is None:
        return False
    parameters = code.co_varnames[: code.co_argcount]
    if not parameters:
        return False
    descriptor_name = parameters[0]
    instructions = list(get_instructions(code))
    for index, instruction in enumerate(instructions):
        if instruction.opname == "LOAD_FAST_LOAD_FAST":
            names = instruction.argval
            if not isinstance(names, tuple) or descriptor_name not in names:
                continue
            if names[-1] != descriptor_name or index + 1 >= len(instructions):
                continue
            if not _descriptor_attribute_read_is_safe(
                instructions[index + 1],
                synthesized_attributes,
            ):
                return False
            continue
        if instruction.opname != "LOAD_FAST":
            continue
        if instruction.argval == descriptor_name and index + 1 < len(instructions):
            next_instruction = instructions[index + 1]
            if next_instruction.opname in {"LOAD_ATTR", "LOAD_METHOD", "STORE_ATTR", "DELETE_ATTR"}:
                if not _descriptor_attribute_read_is_safe(next_instruction, synthesized_attributes):
                    return False
    return True


def _method_code(method: object) -> types.CodeType | None:
    """Return code from raw or payload-backed modeled descriptor methods."""
    raw_func = getattr(method, "func", None)
    payload = function_payload(raw_func)
    if payload is not None:
        return payload.code
    return raw_func if isinstance(raw_func, types.CodeType) else None


def _descriptor_attribute_read_is_safe(
    instruction: dis.Instruction,
    synthesized_attributes: frozenset[str],
) -> bool:
    """Return whether a ``LOAD_ATTR`` reads only a pre-synthesized literal field."""
    if instruction.opname != "LOAD_ATTR":
        return False
    return isinstance(instruction.argval, str) and instruction.argval in synthesized_attributes
