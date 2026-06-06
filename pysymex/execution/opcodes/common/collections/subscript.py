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

"""``STORE_SUBSCR`` and ``DELETE_SUBSCR`` mutation paths for containers.

Complements read lowering in :mod:`pysymex.execution.opcodes.common.collections.read`
with modeled ``__setitem__``/``__delitem__`` dispatch, heap updates, and feasible
exception branches for out-of-range or type errors.
"""

from __future__ import annotations

import dis
from collections.abc import Callable
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.effects.locations import WriteLocation, item_write_location
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.constants import Z3_FALSE
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.helpers import (
    coerce_symbolic_index,
    coerce_symbolic_key,
    coerce_symbolic_value,
    extract_none_expr,
    path_is_sat,
    require_stack_depth,
)
from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler
from pysymex.execution.opcodes.common.collections.read import (
    handle_common_binary_subscr as handle_common_binary_subscr,
)
from pysymex.execution.opcodes.common.collections.protocols import (
    dispatch_modeled_index_protocol,
    dispatch_modeled_subscript_protocol,
)
from pysymex.execution.opcodes.common.collections.slice_mutation import (
    try_delete_retained_slice,
    try_store_retained_slice,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_store_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``STORE_SUBSCR``: pop value, index, container and perform assignment.

    May fork on ``TypeError``/``KeyError`` when handlers exist; uses protocol dispatch
    before precise list/dict mutation or havoc degradation.
    """
    require_stack_depth(state, instr, 3, "STORE_SUBSCR value, container, and key")
    key = state.pop()
    container = state.pop()
    val = state.pop()
    write_location = item_write_location(state, container)
    modeled_result = dispatch_modeled_subscript_protocol(
        state, ctx, container, "__setitem__", [key, val]
    )
    if modeled_result is not None:
        return modeled_result
    real_container: object = container
    container_addr = -1
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container_addr, container)
    if isinstance(real_container, (list, SymbolicList)):
        slice_result = try_store_retained_slice(
            instr, state, ctx, val, container, cast("object", real_container), container_addr, key
        )
        if slice_result is not None:
            return slice_result
        index_result = dispatch_modeled_index_protocol(state, ctx, [val, container], key)
        if index_result is not None:
            return index_result

    symbolic_key = coerce_symbolic_index(key)
    if isinstance(real_container, list):
        try:
            list_setitem = cast(
                "Callable[[StackValue, StackValue], None]",
                cast("list[StackValue]", real_container).__setitem__,
            )
            list_setitem(key, val)
            state = _record_item_write(state, write_location, instr)
        except TypeError as exc:
            return _subscr_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)
        except IndexError as exc:
            return _subscr_exception_result(instr, state, ctx, IssueKind.INDEX_ERROR, exc)

    elif isinstance(real_container, dict):
        try:
            concrete_dict = cast("dict[object, object]", real_container)
            concrete_dict[_concrete_dict_key(key)] = val
            state = _record_item_write(state, write_location, instr)
        except TypeError as exc:
            return _subscr_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)

    elif isinstance(real_container, SymbolicString):
        return _subscr_type_error_result(
            instr,
            state,
            ctx,
            "'str' object does not support item assignment",
        )

    elif isinstance(real_container, SymbolicList) and symbolic_key is not None:
        state = state.add_constraint(
            z3.And(
                symbolic_key.is_int,
                symbolic_key.z3_int >= -real_container.z3_len,
                symbolic_key.z3_int < real_container.z3_len,
            )
        )

        new_container = real_container.__setitem__(symbolic_key, coerce_symbolic_value(val))
        if container_addr != -1:
            state = state.store_heap(container_addr, new_container)
            state = _replace_direct_container_aliases(state, real_container, new_container)
        else:
            state = _replace_direct_container_aliases(state, real_container, new_container)
        state = _record_item_write(state, write_location, instr)

    elif isinstance(real_container, SymbolicDict):
        dict_key = coerce_symbolic_key(key)
        if dict_key is None:
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

        new_container = real_container.__setitem__(dict_key, coerce_symbolic_value(val))
        if container_addr != -1:
            state = state.store_heap(container_addr, new_container)
            state = _replace_direct_container_aliases(state, real_container, new_container)
        else:
            state = _replace_direct_container_aliases(state, real_container, new_container)
        state = _record_item_write(state, write_location, instr)

    else:
        type_error_message = _definite_store_subscr_type_error_message(real_container)
        if type_error_message is not None:
            return _subscr_type_error_result(instr, state, ctx, type_error_message)

        none_expr = extract_none_expr(real_container)
        can_be_none = real_container is None or (
            none_expr is not None and path_is_sat([*state.path_constraints, none_expr])
        )
        if not can_be_none:
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

        must_be_none = real_container is None or not path_is_sat(
            [*state.path_constraints, z3.Not(none_expr if none_expr is not None else Z3_FALSE)]
        )
        is_unconstrained_var = (
            none_expr is not None
            and z3.is_const(none_expr)
            and none_expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
        )

        if must_be_none or not is_unconstrained_var:
            if must_be_none:
                state = state.advance_pc()
                return OpcodeResult.continue_with(state)

        if none_expr is not None:
            state = state.add_constraint(z3.Not(none_expr))

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _replace_direct_container_aliases(
    state: VMState,
    old_container: object,
    new_container: StackValue,
) -> VMState:
    """Refresh symbolic container aliases and source carriers after mutation."""
    from pysymex.execution.opcodes.common.functions.classes import (
        propagate_container_mutation_reference,
    )

    return propagate_container_mutation_reference(state, old_container, new_container)


def _record_item_write(state: VMState, location: WriteLocation, instr: dis.Instruction) -> VMState:
    """Record a successful modeled item write or deletion."""
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, instr.opname)
    )


def _definite_store_subscr_type_error_message(container: object) -> str | None:
    """Return a definite CPython ``STORE_SUBSCR`` ``TypeError`` message, if any."""
    if container is None or isinstance(container, SymbolicNone):
        return "'NoneType' object does not support item assignment"
    if isinstance(container, (str, tuple, bytes, int, float, bool)):
        type_name = type(cast("object", container)).__name__
        return f"'{type_name}' object does not support item assignment"
    if isinstance(container, SymbolicValue):
        if z3.is_true(z3.simplify(container.is_none)):
            return "'NoneType' object does not support item assignment"
        if container.affinity_type in {"int", "float", "bool", "str"}:
            return f"'{container.affinity_type}' object does not support item assignment"
        if z3.is_true(z3.simplify(container.is_str)):
            return "'str' object does not support item assignment"
    return None


def _subscr_type_error_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    message: str,
) -> OpcodeResult:
    """Route a definite subscript ``TypeError`` through handler or issue reporting."""
    return _subscr_exception_result(
        instr,
        state,
        ctx,
        IssueKind.TYPE_ERROR,
        TypeError(message),
    )


def _subscr_exception_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    kind: IssueKind,
    exc: Exception,
) -> OpcodeResult:
    """Route a subscript exception to a handler or emit a possible-issue report."""
    modeled_exc = SymbolicException.concrete(type(exc), str(exc), raised_at=state.pc)
    handler_state = jump_to_exception_handler(state, ctx, instr.offset, modeled_exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    issue = Issue(
        kind=kind,
        message=f"Possible {type(exc).__name__}: {exc}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def _concrete_dict_key(key: StackValue) -> object:
    """Return a concrete hash key for definite symbolic scalar keys."""
    if isinstance(key, SymbolicString) and z3.is_string_value(key.z3_str):
        return key.z3_str.as_string()
    if isinstance(key, SymbolicValue):
        if key.value is not None:
            return key.value
        if z3.is_true(z3.simplify(key.is_none)):
            return None
        if z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        if z3.is_int_value(key.z3_int):
            return key.z3_int.as_long()
    return key


def handle_common_delete_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``DELETE_SUBSCR``: pop index and container and remove the item.

    Mirrors store paths for modeled containers; may branch to exception handlers when
    deletion can fail under symbolic indices.
    """
    require_stack_depth(state, instr, 2, "DELETE_SUBSCR container and key")
    key = state.pop()
    container = state.pop()
    write_location = item_write_location(state, container)
    modeled_result = dispatch_modeled_subscript_protocol(
        state, ctx, container, "__delitem__", [key]
    )
    if modeled_result is not None:
        return modeled_result
    real_container = container
    container_addr = -1
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container_addr, container)
    if isinstance(real_container, (list, SymbolicList)):
        slice_result = try_delete_retained_slice(
            instr, state, ctx, container, cast("object", real_container), container_addr, key
        )
        if slice_result is not None:
            return slice_result
        index_result = dispatch_modeled_index_protocol(state, ctx, [container], key)
        if index_result is not None:
            return index_result

    if isinstance(real_container, list):
        try:
            list_delitem = cast(
                "Callable[[StackValue], None]",
                cast("list[StackValue]", real_container).__delitem__,
            )
            list_delitem(key)
            state = _record_item_write(state, write_location, instr)
        except TypeError as exc:
            return _subscr_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)
        except IndexError as exc:
            return _subscr_exception_result(instr, state, ctx, IssueKind.INDEX_ERROR, exc)

    elif isinstance(real_container, dict):
        try:
            del cast("dict[object, object]", real_container)[_concrete_dict_key(key)]
            state = _record_item_write(state, write_location, instr)
        except TypeError as exc:
            return _subscr_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)
        except KeyError as exc:
            return _subscr_exception_result(instr, state, ctx, IssueKind.KEY_ERROR, exc)

    elif isinstance(real_container, SymbolicString):
        return _subscr_type_error_result(
            instr,
            state,
            ctx,
            "'str' object doesn't support item deletion",
        )

    elif isinstance(real_container, SymbolicDict):
        dict_key = coerce_symbolic_key(key)
        if dict_key is not None:
            state = state.add_constraint(real_container.contains_key(dict_key).z3_bool)
            new_container = real_container.__delitem__(dict_key)
            if container_addr != -1:
                state = state.store_heap(container_addr, new_container)
                state = _replace_direct_container_aliases(state, real_container, new_container)
            else:
                state = _replace_direct_container_aliases(state, real_container, new_container)
            state = _record_item_write(state, write_location, instr)
    elif isinstance(real_container, SymbolicList):
        symbolic_key = coerce_symbolic_index(key)
        if symbolic_key is not None:
            state = state.add_constraint(
                z3.And(
                    symbolic_key.is_int,
                    symbolic_key.z3_int >= -real_container.z3_len,
                    symbolic_key.z3_int < real_container.z3_len,
                )
            )
            new_container = real_container.__delitem__(symbolic_key)
            if container_addr != -1:
                state = state.store_heap(container_addr, new_container)
                state = _replace_direct_container_aliases(state, real_container, new_container)
            else:
                state = _replace_direct_container_aliases(state, real_container, new_container)
            state = _record_item_write(state, write_location, instr)
    else:
        type_error_message = _definite_delete_subscr_type_error_message(real_container)
        if type_error_message is not None:
            return _subscr_type_error_result(instr, state, ctx, type_error_message)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _definite_delete_subscr_type_error_message(container: object) -> str | None:
    """Return a definite CPython ``DELETE_SUBSCR`` ``TypeError`` message, if any."""
    if container is None or isinstance(container, SymbolicNone):
        return "'NoneType' object does not support item deletion"
    if isinstance(container, (str, tuple, bytes)):
        type_name = type(cast("object", container)).__name__
        return f"'{type_name}' object doesn't support item deletion"
    if isinstance(container, (int, float, bool)):
        type_name = type(cast("object", container)).__name__
        return f"'{type_name}' object does not support item deletion"
    if isinstance(container, SymbolicValue):
        if z3.is_true(z3.simplify(container.is_none)):
            return "'NoneType' object does not support item deletion"
        if container.affinity_type in {"int", "float", "bool"}:
            return f"'{container.affinity_type}' object does not support item deletion"
        if container.affinity_type == "str" or z3.is_true(z3.simplify(container.is_str)):
            return "'str' object doesn't support item deletion"
    return None
