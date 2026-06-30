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

"""Guarded raise recognition for source predicates called from generator expressions."""

from __future__ import annotations

import builtins
import types
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.calls.payload import function_payload
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState


@dataclass(frozen=True, slots=True)
class PotentialRaise:
    """A precise predicate exception condition usable as a model side effect."""

    type_name: str
    message: str
    condition: z3.BoolRef


@dataclass(frozen=True, slots=True)
class _RaisedException:
    type_name: str
    message: str


def predicate_potential_raise(
    predicate: object,
    args: list[object],
    state: VMState,
) -> PotentialRaise | None:
    """Infer a simple guarded ``raise`` path for *predicate* called with *args*."""
    code = _function_code(predicate)
    if code is None:
        return None
    arg_count = code.co_argcount
    if len(args) < arg_count:
        return None
    locals_by_name = dict(zip(code.co_varnames[:arg_count], args[:arg_count], strict=False))
    globals_by_name = _function_globals(predicate, state)
    instructions = list(get_instructions(code))
    raise_index = next(
        (
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname == "RAISE_VARARGS"
        ),
        None,
    )
    stack: list[object] = []
    guards: list[z3.BoolRef] = []
    scan_end = raise_index + 1 if raise_index is not None else len(instructions)
    raise_offset = instructions[raise_index].offset if raise_index is not None else None
    for instruction in instructions[:scan_end]:
        opname = instruction.opname
        if opname in {"RESUME", "CACHE", "NOP", "PRECALL", "PUSH_NULL"}:
            continue
        if opname in {"LOAD_FAST", "LOAD_FAST_CHECK"}:
            stack.append(locals_by_name.get(str(instruction.argval)))
            continue
        if opname == "LOAD_FAST_LOAD_FAST":
            names = instruction.argval
            if not isinstance(names, tuple):
                return None
            names_tuple = cast("tuple[object, ...]", names)
            for name in names_tuple:
                stack.append(locals_by_name.get(str(name)))
            continue
        if opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
            stack.append(globals_by_name.get(str(instruction.argval)))
            continue
        if opname == "LOAD_CONST":
            stack.append(instruction.argval)
            continue
        if opname == "COMPARE_OP":
            if len(stack) < 2:
                return None
            right = stack.pop()
            left = stack.pop()
            condition = _compare_values(left, _compare_op_name(instruction), right)
            if condition is None:
                return None
            stack.append(condition)
            continue
        if opname in {
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_FORWARD_IF_FALSE",
            "POP_JUMP_BACKWARD_IF_FALSE",
        }:
            if not stack:
                return None
            condition = _as_bool_ref(stack.pop())
            if condition is None:
                return None
            target = instruction.argval
            if isinstance(target, int) and raise_offset is not None and target > raise_offset:
                guards.append(condition)
            continue
        if opname == "CALL":
            argc = instruction.arg if isinstance(instruction.arg, int) else 0
            if len(stack) < argc + 1:
                return None
            call_args = [stack.pop() for _ in range(argc)]
            call_args.reverse()
            callee = stack.pop()
            exc_name = _exception_type_name(callee)
            if exc_name is not None:
                message = str(call_args[0]) if call_args else ""
                stack.append(_RaisedException(exc_name, message))
                continue
            nested = predicate_potential_raise(callee, call_args, state)
            if nested is not None:
                condition = z3.And(*guards, nested.condition) if guards else nested.condition
                return PotentialRaise(nested.type_name, nested.message, simplify_expr(condition))
            return None
        if opname == "RAISE_VARARGS":
            return _build_potential_raise(instruction, stack, guards)
        return None
    return None


def _build_potential_raise(
    instruction: dis.Instruction,
    stack: list[object],
    guards: list[z3.BoolRef],
) -> PotentialRaise | None:
    argc = instruction.arg if isinstance(instruction.arg, int) else 0
    if argc == 0 or len(stack) < argc:
        return None
    exc = stack[-argc]
    condition = simplify_expr(z3.And(*guards)) if guards else Z3_TRUE
    if isinstance(exc, _RaisedException):
        return PotentialRaise(exc.type_name, exc.message, condition)
    exc_name = _exception_type_name(exc)
    if exc_name is None:
        return None
    return PotentialRaise(exc_name, "", condition)


def _function_code(function: object) -> types.CodeType | None:
    payload = function_payload(getattr(function, "_modeled_object", function))
    if payload is not None:
        return payload.code
    code = getattr(function, "__code__", None) or getattr(function, "_func_code", None)
    return code if isinstance(code, types.CodeType) else None


def _function_globals(function: object, state: VMState) -> dict[str, object]:
    globals_obj = getattr(function, "__globals__", None)
    merged: dict[str, object] = dict(_builtin_exception_types().items())
    merged.update({str(name): value for name, value in state.global_vars.items()})
    if isinstance(globals_obj, dict):
        globals_map = cast("dict[object, object]", globals_obj)
        for name, value in globals_map.items():
            if isinstance(name, str):
                merged[name] = value
    return merged


def _builtin_exception_types() -> dict[str, type[BaseException]]:
    exceptions: dict[str, type[BaseException]] = {}
    for name, value in vars(builtins).items():
        if not isinstance(value, type):
            continue
        try:
            if issubclass(value, BaseException):
                exceptions[name] = value
        except TypeError:
            continue
    return exceptions


def _compare_op_name(instruction: dis.Instruction) -> str:
    op_name = str(instruction.argrepr or instruction.argval)
    if op_name.startswith("bool(") and op_name.endswith(")"):
        return op_name[5:-1]
    return op_name


def _as_bool_ref(value: object) -> z3.BoolRef | None:
    if isinstance(value, z3.BoolRef):
        return value
    if isinstance(value, bool):
        return Z3_TRUE if value else Z3_FALSE
    return None


def _compare_values(left: object, op_name: str, right: object) -> z3.BoolRef | None:
    if isinstance(left, SymbolicValue):
        return _compare_symbolic_to_const(left, op_name, right)
    if isinstance(right, SymbolicValue):
        return _compare_symbolic_to_const(right, _reverse_op(op_name), left)
    try:
        return Z3_TRUE if _compare_concrete(left, op_name, right) else Z3_FALSE
    except TypeError:
        return None


def _compare_symbolic_to_const(
    value: SymbolicValue,
    op_name: str,
    constant: object,
) -> z3.BoolRef | None:
    if isinstance(constant, bool):
        constant = int(constant)
    if isinstance(constant, int):
        numeric_expr = z3.If(
            value.is_bool,
            z3.If(value.z3_bool, ConstraintValues.int(1), ConstraintValues.int(0)),
            value.z3_int,
        )
        return z3.And(
            z3.Or(value.is_int, value.is_bool),
            _compare_arith(numeric_expr, op_name, ConstraintValues.int(constant)),
        )
    if isinstance(constant, str) and op_name in {"==", "!="}:
        condition = z3.And(value.is_str, value.z3_str == ConstraintValues.string(constant))
        return z3.Not(condition) if op_name == "!=" else condition
    if constant is None and op_name in {"==", "!="}:
        condition = value.is_none
        return z3.Not(condition) if op_name == "!=" else condition
    return None


def _compare_arith(left: z3.ArithRef, op_name: str, right: z3.ArithRef) -> z3.BoolRef:
    if op_name == "==":
        return left == right
    if op_name == "!=":
        return left != right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    msg = f"unsupported comparison op: {op_name}"
    raise TypeError(msg)


def _compare_concrete(left: object, op_name: str, right: object) -> bool:
    if op_name == "==":
        return left == right
    if op_name == "!=":
        return left != right
    if isinstance(left, (int, float, bool)) and isinstance(right, (int, float, bool)):
        return _compare_numeric(left, op_name, right)
    if isinstance(left, str) and isinstance(right, str):
        return _compare_string(left, op_name, right)
    if isinstance(left, bytes) and isinstance(right, bytes):
        return _compare_bytes(left, op_name, right)
    left_type = type(left).__name__
    right_type = type(right).__name__
    msg = f"unsupported comparison operands: {left_type}, {right_type}"
    raise TypeError(msg)


def _compare_numeric(left: float | bool, op_name: str, right: float | bool) -> bool:
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    msg = f"unsupported comparison op: {op_name}"
    raise TypeError(msg)


def _compare_string(left: str, op_name: str, right: str) -> bool:
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    msg = f"unsupported comparison op: {op_name}"
    raise TypeError(msg)


def _compare_bytes(left: bytes, op_name: str, right: bytes) -> bool:
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    msg = f"unsupported comparison op: {op_name}"
    raise TypeError(msg)


def _reverse_op(op_name: str) -> str:
    return {">": "<", ">=": "<=", "<": ">", "<=": ">="}.get(op_name, op_name)


def _exception_type_name(value: object) -> str | None:
    exc_type = _as_base_exception_type(value)
    if exc_type is not None:
        return exc_type.__name__
    name = getattr(value, "__name__", None)
    if isinstance(name, str) and ("Error" in name or "Exception" in name):
        return name
    type_name = getattr(value, "type_name", None)
    if isinstance(type_name, str) and ("Error" in type_name or "Exception" in type_name):
        return type_name
    return None


def _as_base_exception_type(value: object) -> type[BaseException] | None:
    if not isinstance(value, type):
        return None
    try:
        if issubclass(value, BaseException):
            return value
    except TypeError:
        return None
    return None
