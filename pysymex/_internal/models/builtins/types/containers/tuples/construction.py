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

"""Tuple construction symbolic model."""

from __future__ import annotations

import dataclasses
import dis
from typing import TYPE_CHECKING, Protocol, cast

from pysymex._internal.core.bytecode import resolve_binary_op_symbol
from pysymex._internal.core.calls.payload import function_payload
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.consumption import (
    exhausted_iterator,
    iterator_mutation_side_effect,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class _AttributeProvider(Protocol):
    def get_attribute(
        self,
        name: str,
        bound_instance: object | None = None,
    ) -> tuple[object, bool]:
        """Return a retained modeled attribute and whether it exists."""
        ...


class TupleConstructorModel(FunctionModel):
    """Model for tuple() constructor."""

    name = "tuple"
    qualname = "builtins.tuple"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple() constructor."""
        result, constraint = SymbolicList.symbolic(f"tuple_{state.pc}")
        result = dataclasses.replace(result, _type="tuple")
        if len(args) > 1 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.tuple",
                    "tuple() accepts at most one argument",
                ),
            )
        if args and (args[0] is None or isinstance(args[0], (int, float, bool))):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.tuple",
                    "tuple() argument is not iterable",
                ),
            )
        if args:
            value = SymbolicObject.resolve(args[0], state)
            if isinstance(value, SymbolicList):
                return ModelResult(value=dataclasses.replace(value.copy(), _type="tuple"))
            if isinstance(value, ModeledGenerator):
                copied = _copy_finite_generator_expression(value, state)
                if copied is not None:
                    return ModelResult(value=copied)
            if isinstance(value, SymbolicIterator) and not value.is_generator:
                concrete_items = IterationSources.remaining_iterator_items(value, state)
                updated_iterator = exhausted_iterator(value, state)
                if concrete_items is not None and updated_iterator is not None:
                    copied = _copy_tuple_constructor_sequence(concrete_items)
                    if copied is not None:
                        return ModelResult(
                            value=copied,
                            side_effects=iterator_mutation_side_effect(
                                value,
                                updated_iterator,
                            ),
                        )
            concrete_items = IterationSources.iterable_items(value, state)
            if concrete_items is not None:
                copied = _copy_tuple_constructor_sequence(concrete_items)
                if copied is not None:
                    return ModelResult(value=copied)
            if isinstance(value, (list, tuple)):
                copied = _copy_tuple_constructor_sequence(cast("Sequence[object]", value))
                if copied is not None:
                    return ModelResult(value=copied)
        constraints = [constraint]
        if not args:
            constraints.append(result.z3_len == 0)
        return ModelResult(value=result, constraints=constraints)


def _copy_tuple_constructor_sequence(value: Sequence[object]) -> SymbolicList | None:
    copied = list(value)
    if all(_can_retain_tuple_constructor_item(item) for item in copied):
        return dataclasses.replace(SymbolicList.from_const(copied), _type="tuple")
    return None


def _copy_finite_generator_expression(
    generator: ModeledGenerator,
    state: VMState,
) -> SymbolicList | None:
    """Materialize simple finite generator expressions consumed by tuple()."""
    if generator.started or generator.closed or generator.kwargs or len(generator.args) != 1:
        return None
    source = generator.args[0]
    if not isinstance(source, SymbolicIterator):
        return None
    source_items = IterationSources.remaining_iterator_items(source, state)
    if source_items is None:
        return None

    instructions = _generator_instructions(generator)
    if instructions is None or _has_filter_or_complex_jump(instructions):
        return None

    yielded_var = _yielded_fast_var(instructions)
    loop_sources = _loop_source_vars(instructions)
    if yielded_var is not None and loop_sources == [".0"]:
        return _copy_tuple_constructor_sequence(source_items)
    if yielded_var is not None and len(loop_sources) == 2 and loop_sources[0] == ".0":
        flattened = _flatten_one_level(source_items, state)
        if flattened is not None:
            return _copy_tuple_constructor_sequence(flattened)
    if yielded_var is None and loop_sources == [".0"]:
        transformed = _copy_fast_plus_closure_attr_generator(
            generator,
            instructions,
            source_items,
            state,
        )
        if transformed is not None:
            return _copy_tuple_constructor_sequence(transformed)
    return None


def _generator_instructions(generator: ModeledGenerator) -> tuple[dis.Instruction, ...] | None:
    payload = function_payload(generator.function)
    code = payload.code if payload is not None else getattr(generator.function, "__code__", None)
    if code is None or getattr(code, "co_name", None) != "<genexpr>":
        return None
    return tuple(dis.get_instructions(code))


def _has_filter_or_complex_jump(instructions: Iterable[dis.Instruction]) -> bool:
    for instruction in instructions:
        opname = instruction.opname
        if opname.startswith("POP_JUMP") or "JUMP_IF" in opname:
            return True
    return False


def _yielded_fast_var(instructions: Sequence[dis.Instruction]) -> str | None:
    for index, instruction in enumerate(instructions):
        if instruction.opname != "YIELD_VALUE" or index == 0:
            continue
        previous = instructions[index - 1]
        if previous.opname == "LOAD_FAST":
            return str(previous.argval)
        previous_argval: object = previous.argval
        if previous.opname == "STORE_FAST_LOAD_FAST" and isinstance(previous_argval, tuple):
            names = cast("tuple[object, ...]", previous_argval)
            if len(names) >= 2 and names[0] == names[1]:
                return str(names[1])
    return None


def _loop_source_vars(instructions: Sequence[dis.Instruction]) -> list[str]:
    sources: list[str] = []
    for index, instruction in enumerate(instructions):
        if instruction.opname != "GET_ITER" or index == 0:
            continue
        previous = instructions[index - 1]
        if previous.opname == "LOAD_FAST":
            sources.append(str(previous.argval))
    return sources


def _copy_fast_plus_closure_attr_generator(
    generator: ModeledGenerator,
    instructions: Sequence[dis.Instruction],
    source_items: Sequence[StackValue],
    state: VMState,
) -> list[StackValue] | None:
    expression = _yielded_fast_plus_closure_attr(instructions)
    if expression is None:
        return None
    item_var, freevar_name, attr_name = expression
    if item_var not in _stored_loop_vars(instructions):
        return None
    closure_value = _closure_value(generator, freevar_name)
    if closure_value is None:
        return None
    attr_value = _retained_attribute_value(closure_value, attr_name, state)
    if attr_value is None:
        return None

    transformed: list[StackValue] = []
    for item in source_items:
        added = _add_retained_values(item, attr_value)
        if added is None:
            return None
        transformed.append(added)
    return transformed


def _yielded_fast_plus_closure_attr(
    instructions: Sequence[dis.Instruction],
) -> tuple[str, str, str] | None:
    for index, instruction in enumerate(instructions):
        if instruction.opname != "YIELD_VALUE" or index < 4:
            continue
        load_item, load_closure, load_attr, binary_op = instructions[index - 4 : index]
        if load_item.opname not in {"LOAD_FAST", "STORE_FAST_LOAD_FAST"}:
            continue
        if load_closure.opname != "LOAD_DEREF" or load_attr.opname != "LOAD_ATTR":
            continue
        if binary_op.opname != "BINARY_OP" or resolve_binary_op_symbol(binary_op) != "+":
            continue
        item_var = _loaded_fast_name(load_item)
        if item_var is None:
            continue
        return item_var, str(load_closure.argval), str(load_attr.argval)
    return None


def _loaded_fast_name(instruction: dis.Instruction) -> str | None:
    if instruction.opname == "LOAD_FAST":
        return str(instruction.argval)
    raw_argval: object = instruction.argval
    if instruction.opname == "STORE_FAST_LOAD_FAST" and isinstance(raw_argval, tuple):
        names = cast("tuple[object, ...]", raw_argval)
        if len(names) >= 2 and names[0] == names[1]:
            return str(names[1])
    return None


def _stored_loop_vars(instructions: Sequence[dis.Instruction]) -> set[str]:
    names: set[str] = set()
    for instruction in instructions:
        if instruction.opname == "STORE_FAST":
            names.add(str(instruction.argval))
            continue
        raw_argval: object = instruction.argval
        if instruction.opname != "STORE_FAST_LOAD_FAST" or not isinstance(raw_argval, tuple):
            continue
        stored_and_loaded = cast("tuple[object, ...]", raw_argval)
        if stored_and_loaded:
            names.add(str(stored_and_loaded[0]))
    return names


def _closure_value(generator: ModeledGenerator, name: str) -> object | None:
    payload = function_payload(generator.function)
    if payload is None:
        return None
    freevars = tuple(payload.code.co_freevars)
    if name not in freevars:
        return None
    index = freevars.index(name)
    if index >= len(payload.closure):
        return None
    return payload.closure[index]


def _retained_attribute_value(value: object, attr_name: str, state: VMState) -> StackValue | None:
    resolved = SymbolicObject.resolve(cast("StackValue", value), state)
    modeled_object = getattr(resolved, "_modeled_object", resolved)
    get_attribute = getattr(modeled_object, "get_attribute", None)
    if callable(get_attribute):
        provider = cast("_AttributeProvider", modeled_object)
        attr_value, found = provider.get_attribute(attr_name, bound_instance=resolved)
        if found and _can_retain_tuple_constructor_item(attr_value):
            return cast("StackValue", attr_value)
    if hasattr(resolved, attr_name):
        attr_value = getattr(resolved, attr_name)
        if _can_retain_tuple_constructor_item(attr_value):
            return cast("StackValue", attr_value)
    return None


def _add_retained_values(left: StackValue, right: StackValue) -> StackValue | None:
    if isinstance(left, (int, bool)) and isinstance(right, (int, bool)):
        return int(left) + int(right)
    if isinstance(left, (int, bool, SymbolicValue)) and isinstance(
        right,
        (int, bool, SymbolicValue),
    ):
        return SymbolicValue.from_const(left) + SymbolicValue.from_const(right)
    return None


def _flatten_one_level(items: Sequence[object], state: VMState) -> list[StackValue] | None:
    flattened: list[StackValue] = []
    for item in items:
        resolved = SymbolicObject.resolve(cast("StackValue", item), state)
        inner_items = IterationSources.iterable_items(resolved, state)
        if inner_items is None:
            return None
        flattened.extend(inner_items)
    return flattened


def _can_retain_tuple_constructor_item(value: object) -> bool:
    if isinstance(value, SymbolicObject):
        return True
    if isinstance(value, tuple):
        tuple_items = cast("tuple[object, ...]", value)
        return all(_can_retain_tuple_constructor_item(item) for item in tuple_items)
    return isinstance(value, (SymbolicValue, int, bool, str))
