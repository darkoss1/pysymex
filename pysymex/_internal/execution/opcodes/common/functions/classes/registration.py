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

"""Register modeled local classes discovered during symbolic execution.

Links ``SymbolicValue`` type carriers to :class:`~pysymex._internal.core.classes.SymbolicClass`
metadata (bases, ``__match_args__``, init parameters) so subsequent calls and pattern matching
use a stable class object.

Side Effects:
    Mutates global modeled-class registries when a new class body is first seen.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.calls.payload import SymbolicFunctionPayload, function_payload
from pysymex._internal.core.classes.types import InitParameter
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    import types

    from pysymex._internal.core.classes.classes import SymbolicClass


def modeled_class_from_python_type(class_obj: type) -> SymbolicClass:
    """Resolve or register a concrete Python class while preserving its bases."""
    from pysymex._internal.core.classes.classes import SymbolicClass
    from pysymex._internal.core.classes.registry import class_registry
    from pysymex._internal.execution.opcodes.common.functions.classes.descriptors.methods import (
        register_class_body_methods,
    )

    modeled_cls = class_registry.get_class(class_obj.__name__)
    if modeled_cls is not None:
        modeled_cls.set_bases_complete(True)
        register_class_body_methods(modeled_cls, class_obj)
        return modeled_cls

    bases: list[SymbolicClass] = []
    bases_complete = True
    for base in class_obj.__bases__:
        modeled_base = modeled_class_from_python_type(base)
        bases.append(modeled_base)

    modeled_cls = class_registry.register_class(SymbolicClass(class_obj.__name__, bases=bases))
    modeled_cls.set_bases_complete(bases_complete)
    register_class_body_methods(modeled_cls, class_obj)
    return modeled_cls


def modeled_class_from_value(value: SymbolicValue) -> SymbolicClass | None:
    """Resolve or register a modeled class value while preserving its bases."""
    if getattr(value, "affinity_type", None) != "type":
        return None
    payload = function_payload(getattr(value, "_modeled_object", None))
    if payload is None:
        return None
    class_body = payload.code
    closure_by_name = _payload_closure_by_name(payload)
    from pysymex._internal.core.classes.classes import SymbolicClass
    from pysymex._internal.core.classes.registry import class_registry

    modeled_cls = class_registry.get_by_code_object(class_body)
    if modeled_cls is not None:
        return modeled_cls
    class_name = value.name or class_body.co_name
    bases, bases_complete = _declared_bases(value)
    modeled_cls = class_registry.register_class(SymbolicClass(str(class_name), bases=bases))
    modeled_cls.set_bases_complete(bases_complete)
    metaclass_value = getattr(value, "_pysymex_metaclass_value", None)
    if isinstance(metaclass_value, SymbolicValue):
        modeled_metaclass = modeled_class_from_value(metaclass_value)
        if modeled_metaclass is not None:
            modeled_cls.metaclass = modeled_metaclass
    if getattr(value, "_pysymex_trusted_cached_property", False) is True:
        modeled_cls.mark_trusted_cached_property()
    class_registry.register_code_object(class_body, modeled_cls)
    from pysymex._internal.execution.opcodes.common.functions.classes.descriptor.bindings import (
        register_declared_bindings,
    )
    from pysymex._internal.execution.opcodes.common.functions.classes.descriptors.methods import (
        register_class_body_methods,
    )

    contract_decorator_names = _contract_decorator_names_from_value(value)
    register_class_body_methods(
        modeled_cls,
        class_body,
        closure_by_name=closure_by_name,
        contract_decorator_names=contract_decorator_names,
    )
    _register_literal_class_attributes(modeled_cls, class_body)
    _register_literal_enum_members(modeled_cls, value)
    _register_annotation_only_named_tuple(modeled_cls, value)
    _register_bounded_dataclass(modeled_cls, value)
    _register_static_class_attributes(modeled_cls, value)
    register_declared_bindings(modeled_cls, value)
    return modeled_cls


def _payload_closure_by_name(payload: SymbolicFunctionPayload) -> dict[str, object]:
    """Return class-body closure cells keyed by free-variable name."""
    if not payload.closure:
        return {}
    return dict(zip(payload.code.co_freevars, payload.closure, strict=False))


def _contract_decorator_names_from_value(value: SymbolicValue) -> frozenset[str]:
    """Return class-body PySyMex contract decorator names proven during ``__build_class__``."""
    raw_names = getattr(value, "_pysymex_contract_decorator_names", None)
    if not isinstance(raw_names, (frozenset, tuple)):
        return frozenset()
    typed_names = cast("tuple[object, ...] | frozenset[object]", raw_names)
    if all(isinstance(name, str) for name in typed_names):
        return frozenset(str(name) for name in typed_names)
    return frozenset()


def _register_literal_class_attributes(
    modeled_cls: SymbolicClass,
    class_body: types.CodeType,
) -> None:
    """Register direct immutable literal assignments visible in class bytecode."""
    instructions = list(get_instructions(class_body))
    for index, instr in enumerate(instructions):
        if (
            instr.opname not in {"STORE_NAME", "STORE_GLOBAL"}
            or not isinstance(instr.argval, str)
            or index == 0
            or instructions[index - 1].opname != "LOAD_CONST"
        ):
            continue
        value = instructions[index - 1].argval
        if instr.argval == "__match_args__":
            if isinstance(value, tuple):
                match_args = cast("tuple[object, ...]", value)
                if all(isinstance(item, str) for item in match_args):
                    modeled_cls.add_class_attr(instr.argval, cast("tuple[str, ...]", match_args))
            continue
        if instr.argval.startswith("__"):
            continue
        if isinstance(value, (bool, int, float, str, bytes, type(None))):
            modeled_cls.add_class_attr(instr.argval, value)


def _register_literal_enum_members(modeled_cls: SymbolicClass, value: SymbolicValue) -> None:
    """Expose bounded standard enum metadata and numeric IntEnum members."""
    raw_members = getattr(value, "_pysymex_literal_enum_members", None)
    if not isinstance(raw_members, dict):
        return
    enum_values: list[int] = []
    for name, member in cast("dict[object, object]", raw_members).items():
        if not isinstance(name, str) or not isinstance(member, enum.Enum):
            continue
        if type(member.value) is int:
            enum_values.append(member.value)
        if isinstance(member, enum.IntEnum):
            modeled_cls.add_class_attr(name, member, is_readonly=True, type_hint="int")
    if enum_values:
        modeled_cls.literal_enum_values = tuple(enum_values)


def _register_annotation_only_named_tuple(modeled_cls: SymbolicClass, value: SymbolicValue) -> None:
    """Register constructor fields and immutability for bounded typed named tuples."""
    raw_fields = getattr(value, "_pysymex_named_tuple_fields", None)
    if not isinstance(raw_fields, tuple):
        return
    fields = cast("tuple[object, ...]", raw_fields)
    if not all(isinstance(field, str) for field in fields):
        return
    typed_fields = cast("tuple[str, ...]", fields)
    modeled_cls.set_init_params([InitParameter(name=field) for field in typed_fields])
    modeled_cls.named_tuple_fields = typed_fields


def _register_bounded_dataclass(modeled_cls: SymbolicClass, value: SymbolicValue) -> None:
    """Register generated initialization for a source-visible bounded dataclass."""
    raw_fields = getattr(value, "_pysymex_dataclass_fields", None)
    if not isinstance(raw_fields, tuple):
        return
    parameters: list[InitParameter] = []
    for raw_field_value in cast("tuple[object, ...]", raw_fields):
        if not isinstance(raw_field_value, tuple):
            return
        raw_field = cast("tuple[object, ...]", raw_field_value)
        if len(raw_field) != 5:
            return
        name, type_hint, has_default, default, default_factory = raw_field
        if (
            not isinstance(name, str)
            or not (type_hint is None or isinstance(type_hint, str))
            or not isinstance(has_default, bool)
        ):
            return
        if default_factory == "list":
            parameters.append(
                InitParameter(
                    name=name,
                    type_hint=type_hint,
                    default_factory=SymbolicList.empty,
                ),
            )
        else:
            parameters.append(
                InitParameter(
                    name=name,
                    type_hint=type_hint,
                    default=default if has_default else None,
                    has_default=has_default,
                ),
            )
        modeled_cls.dataclass_fields[name] = (type_hint or "object", default)
    modeled_cls.is_dataclass = True
    modeled_cls.dataclass_frozen = bool(getattr(value, "_pysymex_dataclass_frozen", False))
    modeled_cls.set_init_params(parameters)


def _register_static_class_attributes(modeled_cls: SymbolicClass, value: SymbolicValue) -> None:
    """Register statically proven class-hook effects without executing class code."""
    raw_attributes = getattr(value, "_pysymex_static_class_attrs", None)
    if not isinstance(raw_attributes, dict):
        return
    for name, attribute in cast("dict[object, object]", raw_attributes).items():
        if isinstance(name, str) and isinstance(attribute, list):
            modeled_cls.add_class_attr(name, cast("list[object]", attribute))


def _declared_bases(value: SymbolicValue) -> tuple[list[SymbolicClass], bool]:
    """Resolve modeled base classes and completeness from symbolic type metadata."""
    raw_bases = getattr(value, "_pysymex_base_values", ())
    if not isinstance(raw_bases, tuple):
        return [], False
    resolved: list[SymbolicClass] = []
    for candidate in cast("tuple[object, ...]", raw_bases):
        if isinstance(candidate, SymbolicValue):
            modeled_base = modeled_class_from_value(candidate)
        elif isinstance(candidate, type):
            modeled_base = modeled_class_from_python_type(candidate)
        else:
            return resolved, False
        if modeled_base is None:
            return resolved, False
        resolved.append(modeled_base)
    complete = bool(getattr(value, "_pysymex_bases_complete", not raw_bases))
    return resolved, complete
