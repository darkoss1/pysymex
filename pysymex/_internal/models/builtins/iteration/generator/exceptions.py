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

"""Potential exception modeling for generator expressions consumed by truth builtins."""

from __future__ import annotations

import types
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.calls.payload import function_payload
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.contracts.results import ModelResult

from .predicate_raises import predicate_potential_raise
from .sources import generator_code, generator_items

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.generators import ModeledGenerator


@dataclass(frozen=True, slots=True)
class _ValueLoader:
    kind: str
    value: object


@dataclass(frozen=True, slots=True)
class _YieldedCall:
    callee: object
    arg_loaders: tuple[_ValueLoader, ...]


def modeled_generator_call_exceptions(
    *,
    name: str,
    generator: ModeledGenerator,
    state: VMState,
) -> ModelResult | None:
    """Return a symbolic truth result with routed predicate-raise side effects.

    This intentionally handles a narrow CPython-shaped generator expression:
    a finite source iterator whose yielded value is a direct call to a source
    predicate, where that predicate has simple guarded ``raise ExceptionType(...)``
    bytecode. The normal ``any``/``all`` result stays symbolic because the
    predicate return value is not summarized here.
    """
    code = generator_code(generator)
    items = generator_items(generator, state)
    if code is None or items is None:
        return None
    yielded_call = _yielded_direct_call(code, generator, state)
    if yielded_call is None:
        return None

    potential_by_type: dict[tuple[str, str], list[z3.BoolRef]] = {}
    for item in items:
        args = _resolve_call_args(yielded_call.arg_loaders, item, code, generator, state)
        if args is None:
            return None
        potential = predicate_potential_raise(yielded_call.callee, args, state)
        if potential is None:
            return None
        potential_by_type.setdefault((potential.type_name, potential.message), []).append(
            potential.condition,
        )

    effects: list[dict[str, object]] = []
    for (type_name, message), conditions in potential_by_type.items():
        condition = simplify_expr(z3.Or(*conditions))
        if z3.is_false(condition):
            continue
        effects.append({"type": type_name, "message": message, "condition": condition})
    if not effects:
        return None

    result, constraints = ModelResult.symbolic_bool(f"{name}_{state.pc}")
    side_effects: dict[str, object]
    if len(effects) == 1:
        side_effects = {"potential_exception": effects[0]}
    else:
        side_effects = {"potential_exceptions": tuple(effects)}
    return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


def _yielded_direct_call(
    code: types.CodeType,
    generator: ModeledGenerator,
    state: VMState,
) -> _YieldedCall | None:
    instructions = list(get_instructions(code))
    for yield_index, instruction in enumerate(instructions):
        if instruction.opname != "YIELD_VALUE":
            continue
        call_index = _previous_call_index(instructions, yield_index)
        if call_index is None:
            return None
        call = instructions[call_index]
        argc = call.arg if isinstance(call.arg, int) else 0
        if argc < 0:
            return None
        stack_loaders = _call_stack_loaders_before(instructions, call_index, argc)
        if stack_loaders is None:
            return None
        callee_loader = stack_loaders[0]
        callee = _resolve_loader(callee_loader, None, code, generator, state)
        if callee is None:
            return None
        return _YieldedCall(
            callee=callee,
            arg_loaders=stack_loaders[1:],
        )
    return None


def _previous_call_index(instructions: list[dis.Instruction], before_index: int) -> int | None:
    for index in range(before_index - 1, -1, -1):
        if instructions[index].opname == "CALL":
            return index
        if instructions[index].opname not in {"CACHE", "PRECALL", "PUSH_NULL"}:
            continue
    return None


def _call_stack_loaders_before(
    instructions: list[dis.Instruction],
    call_index: int,
    argc: int,
) -> tuple[_ValueLoader, ...] | None:
    stack_loaders: list[_ValueLoader] = []
    index = call_index - 1
    while index >= 0 and len(stack_loaders) < argc + 1:
        instruction = instructions[index]
        if instruction.opname in {"CACHE", "PRECALL", "PUSH_NULL"}:
            index -= 1
            continue
        loaders = _loaders_for_instruction(instruction)
        if loaders is None:
            return None
        stack_loaders[0:0] = list(loaders)
        index -= 1
    if len(stack_loaders) != argc + 1:
        return None
    return tuple(stack_loaders)


def _loaders_for_instruction(instruction: dis.Instruction) -> tuple[_ValueLoader, ...] | None:
    if instruction.opname in {"LOAD_FAST", "LOAD_FAST_CHECK"}:
        return (_ValueLoader("fast", instruction.argval),)
    if instruction.opname == "LOAD_FAST_LOAD_FAST":
        names = instruction.argval
        if not isinstance(names, tuple):
            return None
        return tuple(_ValueLoader("fast", name) for name in cast("tuple[object, ...]", names))
    if instruction.opname == "LOAD_DEREF":
        return (_ValueLoader("deref", instruction.argval),)
    if instruction.opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
        return (_ValueLoader("global", instruction.argval),)
    if instruction.opname == "LOAD_CONST":
        return (_ValueLoader("const", instruction.argval),)
    return None


def _resolve_call_args(
    loaders: tuple[_ValueLoader, ...],
    item: object,
    code: types.CodeType,
    generator: ModeledGenerator,
    state: VMState,
) -> list[object] | None:
    args: list[object] = []
    for loader in loaders:
        value = _resolve_loader(loader, item, code, generator, state)
        if value is None:
            return None
        args.append(value)
    return args


def _resolve_loader(
    loader: _ValueLoader,
    item: object | None,
    code: types.CodeType,
    generator: ModeledGenerator,
    state: VMState,
) -> object | None:
    if loader.kind == "const":
        return loader.value
    if loader.kind == "fast":
        if loader.value in {".0", "implicit0"}:
            return None
        return item
    if loader.kind == "global" and isinstance(loader.value, str):
        return state.global_vars.get(loader.value)
    if loader.kind == "deref" and isinstance(loader.value, str):
        return _closure_value(code, generator, loader.value, state)
    return None


def _closure_value(
    code: types.CodeType,
    generator: ModeledGenerator,
    name: str,
    state: VMState,
) -> object | None:
    try:
        index = tuple(code.co_freevars).index(name)
    except ValueError:
        return None
    payload = function_payload(getattr(generator.function, "_modeled_object", generator.function))
    closure = (
        payload.closure if payload is not None else getattr(generator.function, "__closure__", ())
    )
    if index >= len(closure):
        return None
    cell = closure[index]
    if isinstance(cell, SymbolicObject) and cell.address != -1:
        return state.load_heap(cell.address, cell)
    if isinstance(cell, types.CellType):
        return cell.cell_contents
    return cell
