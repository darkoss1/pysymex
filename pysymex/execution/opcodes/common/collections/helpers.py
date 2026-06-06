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

"""Stack, heap, constraint, and concrete-container helpers for collection opcodes.

Centralizes satisfiability checks, symbolic coercion, unpack arity errors, and
heap alias resolution used by BUILD, mutation, slice, and unpack handlers.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence, Sized
import dis
from typing import TYPE_CHECKING, Protocol, TypeGuard, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.state.types import VMStateError
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.mapping_protocol import (
    extract_modeled_instance_mapping,
)
from pysymex.execution.opcodes.common.path_feasibility import path_is_sat as path_is_sat

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    """Raise :class:`~pysymex.core.state.types.VMStateError` when the stack is too shallow."""
    if len(state.stack) < required_depth:
        raise VMStateError(
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )


def is_object_list(value: object) -> TypeGuard[list[object]]:
    """Narrow *value* to a concrete Python ``list``."""
    return isinstance(value, list)


def is_object_tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    """Narrow *value* to a concrete Python ``tuple``."""
    return isinstance(value, tuple)


def is_object_dict(value: object) -> TypeGuard[dict[object, object]]:
    """Narrow *value* to a concrete Python ``dict``."""
    return isinstance(value, dict)


class ConcreteKeysMapping(Protocol):
    """Concrete mapping protocol CPython uses for dict unpacking."""

    def keys(self) -> object:
        """Return an iterable of mapping keys."""
        ...

    def __getitem__(self, key: object, /) -> object:
        """Return the value for *key* or raise the concrete lookup exception."""
        ...


def has_keys_mapping_protocol(value: object) -> TypeGuard[ConcreteKeysMapping]:
    """Return true when *value* supports CPython's ``keys``/``__getitem__`` mapping path."""
    return callable(getattr(value, "keys", None)) and callable(getattr(value, "__getitem__", None))


def add_lowered_constraints(state: VMState, constraints: list[z3.BoolRef]) -> VMState:
    """Append lowered Z3 constraints to *state* and return the updated state."""
    for constraint in constraints:
        state = state.add_constraint(constraint)
    return state


def apply_heap_updates(state: VMState, updates: list[tuple[int, StackValue]]) -> VMState:
    """Apply a sequence of heap updates while maintaining VMState hash invariants."""
    for address, value in updates:
        state = state.store_heap(address, value)
    return state


def branch_or_terminate_exception(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    exception_condition: z3.BoolRef,
) -> OpcodeResult:
    """Fork to an exception handler or terminate when no handler exists."""
    handler_pc = ctx.find_exception_handler(instr.offset)
    if handler_pc is None:
        return OpcodeResult.terminate()
    error_state = state.fork().add_constraint(exception_condition)
    return OpcodeResult.continue_with(error_state.set_pc(handler_pc))


def as_stack_value(value: object) -> StackValue:
    """Coerce runtime or symbolic values into the VM ``StackValue`` domain."""
    if value is None:
        return None
    if isinstance(
        value,
        (
            SymbolicValue,
            SymbolicNone,
            SymbolicString,
            SymbolicList,
            SymbolicDict,
            SymbolicObject,
            int,
            bool,
            str,
            float,
            bytes,
            type,
            list,
            dict,
            tuple,
        ),
    ):
        return cast("StackValue", value)
    return SymbolicValue.from_const(value)


def coerce_symbolic_value(value: StackValue) -> SymbolicValue:
    """Wrap stack values as :class:`~pysymex.core.types.scalars.values.SymbolicValue`."""
    if isinstance(value, SymbolicValue):
        return value
    if hasattr(value, "type_tag"):
        return SymbolicValue.from_specialized(value)
    return SymbolicValue.from_const(value)


def coerce_symbolic_index(value: StackValue) -> SymbolicValue | None:
    """Return an index-shaped symbolic value when coercion is supported."""
    if isinstance(value, SymbolicValue):
        return value
    if isinstance(value, (int, bool)):
        return SymbolicValue.from_const(int(value))
    return None


def coerce_symbolic_key(value: StackValue) -> SymbolicString | None:
    """Return a dict-key-shaped :class:`~pysymex.core.types.scalars.strings.SymbolicString`."""
    if isinstance(value, SymbolicString):
        return value
    if isinstance(value, str):
        return SymbolicString.from_const(value)
    if isinstance(value, SymbolicValue):
        return SymbolicString(_name=value.name, _unified=value)
    return None


def extract_concrete_sequence(value: object) -> list[object] | tuple[object, ...] | None:
    """Return a concrete sequence backing a stack or modeled container."""
    if is_object_list(value) or is_object_tuple(value):
        return value
    if isinstance(value, SymbolicValue):
        modeled_object = getattr(value, "_modeled_object", None)
        if is_object_list(modeled_object) or is_object_tuple(modeled_object):
            return modeled_object
        const_value = value.value
        if is_object_list(const_value) or is_object_tuple(const_value):
            return const_value
    concrete_items = getattr(value, "_concrete_items", None)
    if is_object_list(concrete_items) or is_object_tuple(concrete_items):
        return concrete_items
    return None


def extract_concrete_mapping(value: object) -> SymbolicDict | dict[object, object] | None:
    """Return a symbolic or concrete mapping used for dict updates."""
    if isinstance(value, SymbolicDict):
        return value
    if is_object_dict(value):
        return dict(value)
    if isinstance(value, Mapping):
        return dict(cast("Mapping[object, object]", value))
    if has_keys_mapping_protocol(value):
        return _extract_keys_mapping(value)
    if isinstance(value, SymbolicValue):
        const_value = value.value
        if is_object_dict(const_value):
            return dict(const_value)
        if isinstance(const_value, Mapping):
            return dict(cast("Mapping[object, object]", const_value))
        if const_value is not None and has_keys_mapping_protocol(const_value):
            return _extract_keys_mapping(const_value)
        modeled_mapping = extract_modeled_instance_mapping(value)
        if modeled_mapping is not None:
            return modeled_mapping
    concrete_items = getattr(value, "_concrete_items", None)
    if is_object_dict(concrete_items):
        return dict(concrete_items)
    return None


def _extract_keys_mapping(value: ConcreteKeysMapping) -> dict[object, object]:
    """Extract a concrete dict through CPython's ``keys``/``__getitem__`` protocol."""
    keys_obj = value.keys()
    try:
        key_iter = iter(cast("Iterable[object]", keys_obj))
    except TypeError as exc:
        owner_type = type(value).__name__
        keys_type = type(keys_obj).__name__
        raise TypeError(f"{owner_type}.keys() returned a non-iterable (type {keys_type})") from exc
    return {key: value[key] for key in key_iter}


def resolve_runtime_container(container: StackValue, state: VMState) -> object:
    """Load heap-backed symbolic objects before container mutation."""
    if isinstance(container, SymbolicObject):
        return state.load_heap(container.address, container)

    if isinstance(container, SymbolicValue):
        modeled_object = getattr(container, "_modeled_object", None)
        if isinstance(modeled_object, SymbolicObject):
            return state.load_heap(modeled_object.address, modeled_object)
        if modeled_object is not None:
            return modeled_object
        const_value = container.value
        if const_value is not None:
            return const_value

    return container


def extract_none_expr(value: object) -> z3.BoolRef | None:
    """Return the Z3 ``is_none`` predicate for a symbolic stack value."""
    if isinstance(value, SymbolicValue):
        return value.is_none
    if isinstance(value, SymbolicObject):
        return value.is_none
    return None


def extract_length_expr(value: object) -> z3.ArithRef | None:
    """Return a length expression for supported container affinities."""
    if isinstance(value, (SymbolicList, SymbolicDict, SymbolicString)):
        return value.z3_len
    if isinstance(value, SymbolicValue):
        if value.affinity_type in {"list", "dict"}:
            return value.z3_int
        if value.affinity_type == "str":
            return z3.Length(value.z3_str)
        if z3.is_true(z3.simplify(value.is_list)) or z3.is_true(z3.simplify(value.is_dict)):
            return value.z3_int
        if z3.is_true(z3.simplify(value.is_str)):
            return z3.Length(value.z3_str)
    return None


def resolve_heap_container(state: VMState, value: StackValue) -> StackValue:
    """Replace heap handles with their stored container when present."""
    if isinstance(value, SymbolicObject) and value.address != -1:
        resolved = state.memory.get(value.address)
        if resolved is not None:
            return as_stack_value(resolved)
    return value


def known_sequence_length(value: object) -> int | None:
    """Return a definite sequence length when it is concrete or a Z3 constant."""
    if isinstance(value, SymbolicList) and z3.is_int_value(value.z3_len):
        return value.z3_len.as_long()
    if isinstance(value, (list, tuple, str, bytes, bytearray, range)):
        return len(cast(Sized, value))
    return None


def unpack_value_at(container: StackValue, index: int) -> StackValue:
    """Read one UNPACK_SEQUENCE element, using havoc when the source is unknown."""
    if isinstance(container, SymbolicList):
        concrete_items = container.concrete_items
        if concrete_items is not None and 0 <= index < len(concrete_items):
            return as_stack_value(concrete_items[index])
        return container[index]

    if isinstance(container, (list, tuple, str, bytes, bytearray, range)):
        return as_stack_value(cast(Sequence[object], container)[index])

    val, _constraint = SymbolicValue.symbolic(f"unpack_item_{index}")
    return val


def unpack_arity_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    *,
    expected: int,
    actual: int,
) -> OpcodeResult:
    """Route arity mismatch to a handler or emit a feasible ``ValueError`` issue."""
    handler_pc = ctx.find_exception_handler(instr.offset)
    if handler_pc is not None:
        return OpcodeResult.continue_with(state.set_pc(handler_pc))

    relation = "not enough" if actual < expected else "too many"
    if actual < expected:
        message = f"{relation} values to unpack (expected {expected}, got {actual})"
    else:
        message = f"{relation} values to unpack (expected {expected})"
    issue = Issue(
        kind=IssueKind.VALUE_ERROR,
        message=f"Possible ValueError: {message}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)
