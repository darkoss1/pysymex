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

"""Class-body method registration and decorator classification."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING

from pysymex._internal.execution.opcodes.common.functions.classes.concrete import (
    register_concrete_type_members,
)
from pysymex._internal.execution.opcodes.common.functions.classes.descriptors.bytecode import (
    class_body_effective_instructions,
    code_const_before_make_function,
    last_make_function_before,
    previous_class_body_store_index,
)
from pysymex._internal.execution.opcodes.common.functions.classes.descriptors.properties import (
    bind_property_descriptors_to_closure,
)
from pysymex._internal.execution.opcodes.common.functions.classes.metadata.contracts import (
    contract_from_class_body_decorators,
)
from pysymex._internal.execution.opcodes.common.functions.classes.metadata.payload import (
    class_body_function_payload,
)
from pysymex._internal.execution.opcodes.common.functions.classes.slots import (
    extract_literal_slots,
)

if TYPE_CHECKING:
    import dis
    from collections.abc import Mapping


def decorated_method_kind(
    instructions: list[dis.Instruction],
    method_name: str,
) -> str | None:
    """Classify ``staticmethod``, ``classmethod``, or ``abstractmethod`` decorations."""
    for index, instr in enumerate(instructions):
        if instr.opname not in {"STORE_NAME", "STORE_GLOBAL"} or instr.argval != method_name:
            continue
        make_index = last_make_function_before(instructions, index)
        if make_index is None:
            continue
        code_index = code_const_before_make_function(instructions, make_index)
        if code_index is None:
            continue
        code_obj = instructions[code_index].argval
        if not isinstance(code_obj, types.CodeType) or code_obj.co_name != method_name:
            continue
        boundary = previous_class_body_store_index(instructions, code_index)
        decorators = {
            str(decorator.argval)
            for decorator in instructions[boundary + 1 : code_index]
            if decorator.opname == "LOAD_NAME" and isinstance(decorator.argval, str)
        }
        if "staticmethod" in decorators:
            return "static"
        if "classmethod" in decorators:
            return "class"
        if "abstractmethod" in decorators:
            return "abstract"
    return None


def register_class_body_methods(
    modeled_cls: object,
    class_body: types.CodeType | type,
    *,
    closure_by_name: Mapping[str, object] | None = None,
    contract_decorator_names: frozenset[str] = frozenset(),
) -> None:
    """Populate modeled methods, slots, and properties from class-body bytecode."""
    try:
        from pysymex._internal.core.classes.classes import SymbolicClass
        from pysymex._internal.core.classes.registry import extract_init_params
        from pysymex._internal.core.classes.types import MethodType
    except ImportError:
        return
    if not isinstance(modeled_cls, SymbolicClass):
        return

    if isinstance(class_body, type):
        register_concrete_type_members(modeled_cls, class_body)
        return

    slots = extract_literal_slots(class_body)
    if slots is not None:
        modeled_cls.slots = slots
    instructions = class_body_effective_instructions(class_body)
    for const in class_body.co_consts:
        if not isinstance(const, types.CodeType):
            continue
        method_name = const.co_name
        if method_name in {"<listcomp>", "<dictcomp>", "<setcomp>", "<genexpr>"}:
            continue
        method_kind = decorated_method_kind(instructions, method_name)
        method_type = MethodType.INSTANCE
        if method_kind == "static":
            method_type = MethodType.STATIC
        elif method_kind == "class":
            method_type = MethodType.CLASS
        elif method_kind == "abstract":
            method_type = MethodType.ABSTRACT
        method_func: object | None = None
        if not _has_unknown_decorator_call(
            instructions,
            const,
            method_kind=method_kind,
            contract_decorator_names=contract_decorator_names,
        ):
            method_func = class_body_function_payload(
                instructions,
                const,
                closure_by_name,
                contract_decorator_names,
            )
        modeled_cls.add_method(
            method_name,
            method_func,
            method_type=method_type,
            parameters=list(const.co_varnames[: const.co_argcount]),
        )
        if method_name == "__init__" and method_func is not None:
            modeled_cls.set_init_params(extract_init_params(const))
    bind_property_descriptors_to_closure(
        modeled_cls,
        class_body,
        closure_by_name=closure_by_name,
        contract_decorator_names=contract_decorator_names,
    )


def _has_unknown_decorator_call(
    instructions: list[dis.Instruction],
    code: types.CodeType,
    *,
    method_kind: str | None,
    contract_decorator_names: frozenset[str],
) -> bool:
    """Return whether a class-body store applies an untrusted decorator to *code*."""
    if not _function_assignment_calls_after_make_function(instructions, code):
        return False
    if method_kind is not None:
        return False
    return (
        contract_from_class_body_decorators(
            instructions,
            code,
            contract_decorator_names,
        )
        is None
    )


def _function_assignment_calls_after_make_function(
    instructions: list[dis.Instruction],
    code: types.CodeType,
) -> bool:
    """Return whether the value stored for *code* is produced by a post-make call."""
    indexes = _function_assignment_indexes(instructions, code)
    if indexes is None:
        return False
    make_index, store_index = indexes
    return any(instr.opname == "CALL" for instr in instructions[make_index + 1 : store_index])


def _function_assignment_indexes(
    instructions: list[dis.Instruction],
    code: types.CodeType,
) -> tuple[int, int] | None:
    """Return ``MAKE_FUNCTION`` and store indexes for a class-body function assignment."""
    code_index = None
    for index, instr in enumerate(instructions):
        if instr.opname == "LOAD_CONST" and instr.argval is code:
            code_index = index
            break
    if code_index is None:
        return None

    make_index = None
    for index in range(code_index + 1, len(instructions)):
        instr = instructions[index]
        if instr.opname == "MAKE_FUNCTION":
            make_index = index
            continue
        if instr.opname in {"STORE_NAME", "STORE_GLOBAL"}:
            if instr.argval == code.co_name and make_index is not None:
                return make_index, index
            return None
        if instr.opname in {"RETURN_VALUE", "RETURN_CONST"}:
            return None
    return None
