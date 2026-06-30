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

"""Class ``__init__`` assignment replay helpers for common function opcodes."""

from __future__ import annotations

import dis
import types
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


def _init_code_is_straight_line(init_code: types.CodeType) -> bool:
    """Return whether ``__init__`` bytecode contains no control-flow jumps."""
    for instr in get_instructions(init_code):
        if instr.opcode in dis.hasjrel or instr.opcode in dis.hasjabs:
            return False
    return True


def _init_method_code(init_method: object) -> types.CodeType | None:
    """Return the code object for a modeled ``__init__`` method."""
    raw_func = getattr(init_method, "func", None)
    if isinstance(raw_func, types.CodeType):
        return raw_func
    func_code = getattr(raw_func, "__code__", None)
    if isinstance(func_code, types.CodeType):
        return func_code
    return None


def _simple_init_assignment_value(
    instructions: list[dis.Instruction],
    store_index: int,
) -> tuple[str, object] | None:
    """Decode a single ``STORE_ATTR`` RHS as a parameter or constant."""
    if store_index < 1:
        return None
    previous = instructions[store_index - 1]
    if previous.opname == "LOAD_FAST_LOAD_FAST":
        names_obj = previous.argval
        if isinstance(names_obj, tuple):
            names = cast("tuple[object, ...]", names_obj)
            if len(names) == 2 and names[1] in {"self", "cls"} and isinstance(names[0], str):
                return ("param", names[0])
        return None
    if previous.opname != "LOAD_FAST" or previous.argval not in {"self", "cls"}:
        return None
    if store_index < 2:
        return None
    value_instr = instructions[store_index - 2]
    if value_instr.opname == "LOAD_FAST" and isinstance(value_instr.argval, str):
        return ("param", value_instr.argval)
    if value_instr.opname == "LOAD_CONST":
        return ("const", value_instr.argval)
    literal_container = _literal_container_init_assignment_value(instructions, store_index - 2)
    if literal_container is not None:
        return ("const", literal_container)
    return None


def _literal_container_init_assignment_value(
    instructions: list[dis.Instruction],
    value_index: int,
) -> object | None:
    """Decode side-effect-free literal containers used as ``__init__`` assignment RHS."""
    if value_index < 0:
        return None
    value_instr = instructions[value_index]
    if value_instr.opname == "BUILD_LIST" and value_instr.arg == 0:
        return SymbolicList.from_const([])
    if value_instr.opname != "LIST_EXTEND" or value_index < 2:
        return None
    builder = instructions[value_index - 2]
    source = instructions[value_index - 1]
    if builder.opname != "BUILD_LIST" or builder.arg != 0:
        return None
    source_argval: object = source.argval
    if source.opname != "LOAD_CONST" or not isinstance(source_argval, tuple):
        return None
    source_values = cast("tuple[object, ...]", source_argval)
    return SymbolicList.from_const(source_values)


def _value_from_init_assignment(
    value_info: tuple[str, object],
    param_values: dict[str, object],
) -> tuple[object, bool]:
    """Materialize one init assignment from decoded parameter metadata."""
    value_kind, value_key = value_info
    if value_kind == "param" and isinstance(value_key, str) and value_key in param_values:
        return param_values[value_key], True
    if value_kind == "const":
        return value_key, True
    return None, False


def _init_condition_expr(condition: object) -> z3.BoolRef | None:
    """Return a boolean Z3 term for a simple init branch condition."""
    if isinstance(condition, bool):
        return Z3_TRUE if condition else Z3_FALSE
    if isinstance(condition, SymbolicValue) and z3.is_true(simplify_expr(condition.is_bool)):
        return condition.z3_bool
    return None


def _conditional_init_value(
    attr_name: str,
    condition: z3.BoolRef,
    true_value: object,
    false_value: object,
) -> object:
    """Merge true/false init RHS values into one symbolic attribute value."""
    if z3.is_true(simplify_expr(condition)):
        return true_value
    if z3.is_false(simplify_expr(condition)):
        return false_value
    true_symbol = SymbolicValue.from_const(true_value)
    false_symbol = SymbolicValue.from_const(false_value)
    return SymbolicValue(
        _name=f"init_{attr_name}",
        z3_int=z3.If(condition, true_symbol.z3_int, false_symbol.z3_int),
        is_int=z3.If(condition, true_symbol.is_int, false_symbol.is_int),
        z3_bool=z3.If(condition, true_symbol.z3_bool, false_symbol.z3_bool),
        is_bool=z3.If(condition, true_symbol.is_bool, false_symbol.is_bool),
        is_float=z3.If(condition, true_symbol.is_float, false_symbol.is_float),
        z3_str=z3.If(condition, true_symbol.z3_str, false_symbol.z3_str),
        is_str=z3.If(condition, true_symbol.is_str, false_symbol.is_str),
        z3_addr=z3.If(condition, true_symbol.z3_addr, false_symbol.z3_addr),
        is_obj=z3.If(condition, true_symbol.is_obj, false_symbol.is_obj),
        is_list=z3.If(condition, true_symbol.is_list, false_symbol.is_list),
        is_dict=z3.If(condition, true_symbol.is_dict, false_symbol.is_dict),
        is_path=z3.If(condition, true_symbol.is_path, false_symbol.is_path),
        is_none=z3.If(condition, true_symbol.is_none, false_symbol.is_none),
        affinity_type=(
            true_symbol.affinity_type
            if true_symbol.affinity_type == false_symbol.affinity_type
            else "unknown"
        ),
    )


def _single_init_assignment_between(
    instructions: list[dis.Instruction],
    *,
    start_index: int,
    end_index: int,
) -> tuple[str, tuple[str, object]] | None:
    """Return the sole ``STORE_ATTR`` in a bytecode slice when unambiguous."""
    assignments: list[tuple[str, tuple[str, object]]] = []
    for index in range(start_index, end_index):
        instr = instructions[index]
        if instr.opname != "STORE_ATTR" or not isinstance(instr.argval, str):
            continue
        value_info = _simple_init_assignment_value(instructions, index)
        if value_info is None:
            return None
        assignments.append((instr.argval, value_info))
    if len(assignments) != 1:
        return None
    return assignments[0]


def _apply_simple_conditional_init_assignments(
    init_code: types.CodeType,
    modeled_cls: object,
    instance: object,
    param_values: dict[str, object],
) -> bool:
    """Replay one if/else ``__init__`` that assigns the same attribute on both branches."""
    set_attribute = getattr(instance, "set_attribute", None)
    if not callable(set_attribute):
        return False
    instructions = list(get_instructions(init_code))
    false_jump_ops = {
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_BACKWARD_IF_FALSE",
    }
    jumps = [instr for instr in instructions if instr.opname in false_jump_ops]
    if len(jumps) != 1:
        return False
    jump = jumps[0]
    jump_index = instructions.index(jump)
    condition_index = jump_index - 1
    if condition_index >= 0 and instructions[condition_index].opname == "TO_BOOL":
        condition_index -= 1
    if condition_index < 0:
        return False
    condition_instr = instructions[condition_index]
    if condition_instr.opname != "LOAD_FAST" or not isinstance(condition_instr.argval, str):
        return False
    condition_value = param_values.get(condition_instr.argval)
    if condition_value is None:
        return False
    condition = _init_condition_expr(condition_value)
    if condition is None:
        return False
    false_start = next(
        (index for index, instr in enumerate(instructions) if instr.offset == jump.argval),
        None,
    )
    if false_start is None or false_start <= jump_index + 1:
        return False
    true_assignment = _single_init_assignment_between(
        instructions,
        start_index=jump_index + 1,
        end_index=false_start,
    )
    false_assignment = _single_init_assignment_between(
        instructions,
        start_index=false_start,
        end_index=len(instructions),
    )
    if true_assignment is None or false_assignment is None:
        return False
    true_attr, true_value_info = true_assignment
    false_attr, false_value_info = false_assignment
    if true_attr != false_attr or _has_modeled_property(modeled_cls, true_attr):
        return False
    true_value, true_found = _value_from_init_assignment(true_value_info, param_values)
    false_value, false_found = _value_from_init_assignment(false_value_info, param_values)
    if not true_found or not false_found:
        return False
    set_attribute(true_attr, _conditional_init_value(true_attr, condition, true_value, false_value))
    return True


def apply_straight_line_init_assignments(
    modeled_cls: object,
    instance: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> bool:
    """Seed modeled instance attributes from a straight-line ``__init__`` when safe."""
    get_method = getattr(modeled_cls, "get_method", None)
    if not callable(get_method) or get_method("__setattr__") is not None:
        return False
    init_method = get_method("__init__")
    init_code = _init_method_code(init_method)
    if init_code is None:
        return False
    parameters = list(getattr(init_method, "parameters", []))
    init_values = getattr(instance, "init_values", {})
    param_values: dict[str, object] = {}
    positional_params = [
        str(name) for name in parameters if isinstance(name, str) and name not in {"self", "cls"}
    ]
    for index, name in enumerate(positional_params):
        if name in kwargs:
            param_values[name] = kwargs[name]
        elif index < len(args):
            param_values[name] = args[index]
        elif isinstance(init_values, dict) and name in init_values:
            param_values[name] = init_values[name]

    if not _init_code_is_straight_line(init_code):
        return _apply_simple_conditional_init_assignments(
            init_code,
            modeled_cls,
            instance,
            param_values,
        )

    set_attribute = getattr(instance, "set_attribute", None)
    if not callable(set_attribute):
        return False
    instructions = list(get_instructions(init_code))
    assignments: list[tuple[str, object]] = []
    for index, instr in enumerate(instructions):
        if instr.opname != "STORE_ATTR" or not isinstance(instr.argval, str):
            continue
        if _has_modeled_property(modeled_cls, instr.argval):
            return False
        value_info = _simple_init_assignment_value(instructions, index)
        if not isinstance(value_info, tuple) or len(value_info) != 2:
            return False
        value_kind, value_key = value_info
        if value_kind == "param" and isinstance(value_key, str) and value_key in param_values:
            assignments.append((instr.argval, param_values[value_key]))
        elif value_kind == "const":
            assignments.append((instr.argval, value_key))
        else:
            return False
    for attr_name, value in assignments:
        set_attribute(attr_name, value)
    return bool(assignments)


def _has_modeled_property(modeled_cls: object, attr_name: str) -> bool:
    """Return whether assigning *attr_name* would dispatch through a property descriptor."""
    properties = getattr(modeled_cls, "properties", None)
    return isinstance(properties, dict) and attr_name in properties
