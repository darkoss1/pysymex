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

"""``STORE_SUBSCR`` mutation paths for concrete and modeled containers."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.effects.locations import WriteLocation, item_write_location
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.affinity import (
    SUBSCRIPT_MUTATION_UNSUPPORTED_AFFINITIES,
    python_type_name_for_affinity,
)
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.capabilities import none_expr, symbolic_affinity
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.stack_coercion import StackValuePolicy
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    append_fallback_events,
    may_be_feasible,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.collections.hashability import (
    concrete_unhashable_type_error,
    requires_symbolic_object_hashing,
)
from pysymex._internal.execution.opcodes.common.collections.protocols.index import (
    route_modeled_index,
)
from pysymex._internal.execution.opcodes.common.collections.protocols.subscript import (
    route_modeled_subscript,
)
from pysymex._internal.execution.opcodes.common.collections.slice.mutation import (
    try_store_retained_slice,
)
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.collections.subscript.shared import (
    concrete_dict_key,
    record_item_write,
    replace_direct_container_aliases,
    subscript_exception_result,
    symbolic_dict_subscript_keys,
    symbolic_list_mutation_result,
    unsupported_dict_hashing,
)
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability


if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def _path_satisfiability_result(
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> SolverResult:
    return PathSatisfiability.result(constraints, known_sat_prefix_len=known_sat_prefix_len)


STORE_SUBSCR_NONE_FEASIBILITY_UNKNOWN = "store_subscr_none_feasibility_unknown"
_STORE_SUBSCR_NONE_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=STORE_SUBSCR_NONE_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.collections",
    subject="STORE_SUBSCR None/non-None",
)


def _resolved_store_container(
    state: VMState,
    container: StackValue,
) -> tuple[object, int]:
    """Resolve SymbolicObject containers to heap payloads for STORE_SUBSCR."""
    if isinstance(container, SymbolicObject):
        return state.load_heap(container.address, container), container.address
    return container, -1


def _dispatch_store_subscr_protocols(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    val: StackValue,
    container: StackValue,
    key: StackValue,
    real_container: object,
    container_addr: int,
) -> OpcodeResult | None:
    """Dispatch modeled ``__setitem__``, retained slices, and index protocol paths."""
    modeled_result = route_modeled_subscript(
        state,
        ctx,
        container,
        "__setitem__",
        [key, val],
    )
    if modeled_result is not None:
        return modeled_result
    if not isinstance(real_container, (list, SymbolicList)):
        return None
    slice_result = try_store_retained_slice(
        instr,
        state,
        ctx,
        val,
        container,
        cast("object", real_container),
        container_addr,
        key,
    )
    if slice_result is not None:
        return slice_result
    return route_modeled_index(state, ctx, [val, container], key)


def _store_concrete_list_item(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: list[object],
    key: StackValue,
    val: StackValue,
    write_location: WriteLocation,
) -> VMState | OpcodeResult:
    """Apply concrete list item assignment or route CPython exceptions."""
    try:
        list_setitem = cast(
            "Callable[[StackValue, StackValue], None]",
            cast("list[StackValue]", real_container).__setitem__,
        )
        list_setitem(key, val)
        return record_item_write(state, write_location, instr)
    except TypeError as exc:
        return subscript_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)
    except IndexError as exc:
        return subscript_exception_result(instr, state, ctx, IssueKind.INDEX_ERROR, exc)


def _store_concrete_dict_item(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: dict[object, object],
    key: StackValue,
    val: StackValue,
    write_location: WriteLocation,
) -> VMState | OpcodeResult:
    """Apply concrete dict item assignment or route CPython exceptions."""
    try:
        real_container[concrete_dict_key(key)] = val
        return record_item_write(state, write_location, instr)
    except TypeError as exc:
        return subscript_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)


def _store_symbolic_list_item(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: SymbolicList,
    symbolic_key: SymbolicValue,
    val: StackValue,
    container_addr: int,
    write_location: WriteLocation,
) -> OpcodeResult:
    """Apply symbolic list mutation with alias/heap refresh."""

    def apply_symbolic_list_store(success_state: VMState) -> VMState:
        new_container = real_container.__setitem__(
            symbolic_key,
            StackValuePolicy.as_symbolic(val),
        )
        if container_addr != -1:
            success_state = success_state.store_heap(container_addr, new_container)
        success_state = replace_direct_container_aliases(
            success_state,
            real_container,
            new_container,
        )
        return record_item_write(success_state, write_location, instr)

    return symbolic_list_mutation_result(
        instr,
        state,
        ctx,
        real_container,
        symbolic_key,
        apply_symbolic_list_store,
    )


def _store_symbolic_dict_item(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: SymbolicDict,
    key: StackValue,
    val: StackValue,
    container_addr: int,
    write_location: WriteLocation,
) -> OpcodeResult | VMState:
    """Apply symbolic dict mutation or route unsupported key hashing."""
    type_error_message = concrete_unhashable_type_error(key)
    if type_error_message is not None:
        return subscript_exception_result(
            instr,
            state,
            ctx,
            IssueKind.TYPE_ERROR,
            TypeError(type_error_message),
        )
    if requires_symbolic_object_hashing(key):
        return unsupported_dict_hashing(
            state,
            reason="STORE_SUBSCR dict key requires symbolic or modeled object hashing",
        )

    mutation_key, _storage_key = symbolic_dict_subscript_keys(key)
    new_container = real_container.__setitem__(mutation_key, val)
    if container_addr != -1:
        state = state.store_heap(container_addr, new_container)
    state = replace_direct_container_aliases(state, real_container, new_container)
    return record_item_write(state, write_location, instr)


def _handle_unknown_store_subscr_target(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: object,
) -> OpcodeResult:
    """Handle non-modeled STORE_SUBSCR targets and symbolic None splits."""
    type_error_message = _definite_store_subscr_type_error(real_container)
    if type_error_message is not None:
        return subscript_exception_result(
            instr,
            state,
            ctx,
            IssueKind.TYPE_ERROR,
            TypeError(type_error_message),
        )

    container_none_expr = none_expr(real_container)
    none_result = None
    non_none_result = None
    if container_none_expr is not None:
        none_result = _path_satisfiability_result(
            [*state.path_constraints, container_none_expr],
            known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
        )
    can_be_none = real_container is None or (
        none_result is not None and may_be_feasible(none_result)
    )
    if not can_be_none:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if container_none_expr is not None:
        non_none_result = _path_satisfiability_result(
            [*state.path_constraints, z3.Not(container_none_expr)],
            known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
        )
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_STORE_SUBSCR_NONE_FEASIBILITY_SPEC,
        branches=[
            *([] if none_result is None else [FeasibilityBranch("none", none_result)]),
            *([] if non_none_result is None else [FeasibilityBranch("non_none", non_none_result)]),
        ],
    )
    must_be_none = real_container is None or (
        non_none_result is not None and not may_be_feasible(non_none_result)
    )
    is_unconstrained_var = (
        container_none_expr is not None
        and z3.is_const(container_none_expr)
        and container_none_expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
    )
    if must_be_none or not is_unconstrained_var:
        if must_be_none:
            state = state.advance_pc()
            return append_fallback_events(OpcodeResult.continue_with(state), fallback_events)
    if container_none_expr is not None:
        state = state.add_constraint(z3.Not(container_none_expr))
    state = state.advance_pc()
    return append_fallback_events(OpcodeResult.continue_with(state), fallback_events)


def handle_common_store_subscr(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``STORE_SUBSCR``: pop value, index, container and perform assignment."""
    CollectionStackOps.require_depth(state, instr, 3, "STORE_SUBSCR value, container, and key")
    key = state.pop()
    container = state.pop()
    val = state.pop()
    write_location = item_write_location(state, container)
    real_container, container_addr = _resolved_store_container(state, container)

    protocol_result = _dispatch_store_subscr_protocols(
        instr,
        state,
        ctx,
        val,
        container,
        key,
        real_container,
        container_addr,
    )
    if protocol_result is not None:
        return protocol_result

    symbolic_key = StackValuePolicy.as_index(key)
    if isinstance(real_container, list):
        list_result = _store_concrete_list_item(
            instr,
            state,
            ctx,
            cast("list[object]", real_container),
            key,
            val,
            write_location,
        )
        if isinstance(list_result, OpcodeResult):
            return list_result
        state = list_result
    elif isinstance(real_container, dict):
        dict_result = _store_concrete_dict_item(
            instr,
            state,
            ctx,
            cast("dict[object, object]", real_container),
            key,
            val,
            write_location,
        )
        if isinstance(dict_result, OpcodeResult):
            return dict_result
        state = dict_result
    elif isinstance(real_container, SymbolicString):
        return subscript_exception_result(
            instr,
            state,
            ctx,
            IssueKind.TYPE_ERROR,
            TypeError("'str' object does not support item assignment"),
        )
    elif isinstance(real_container, SymbolicList) and symbolic_key is not None:
        return _store_symbolic_list_item(
            instr,
            state,
            ctx,
            real_container,
            symbolic_key,
            val,
            container_addr,
            write_location,
        )
    elif isinstance(real_container, SymbolicDict):
        dict_result = _store_symbolic_dict_item(
            instr,
            state,
            ctx,
            real_container,
            key,
            val,
            container_addr,
            write_location,
        )
        if isinstance(dict_result, OpcodeResult):
            return dict_result
        state = dict_result
    else:
        return _handle_unknown_store_subscr_target(instr, state, ctx, real_container)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _definite_store_subscr_type_error(container: object) -> str | None:
    """Return a definite CPython ``STORE_SUBSCR`` ``TypeError`` message, if any."""
    if container is None or isinstance(container, SymbolicNoneType):
        return "'NoneType' object does not support item assignment"
    if isinstance(container, (str, tuple, bytes, int, float, bool)):
        type_name = type(cast("object", container)).__name__
        return f"'{type_name}' object does not support item assignment"
    if isinstance(container, SymbolicValue):
        if z3.is_true(simplify_expr(container.is_none)):
            return "'NoneType' object does not support item assignment"
        if container.affinity_type in {"int", "float", "bool", "str"}:
            return f"'{container.affinity_type}' object does not support item assignment"
        if z3.is_true(simplify_expr(container.is_str)):
            return "'str' object does not support item assignment"
    affinity = symbolic_affinity(container)
    if affinity in SUBSCRIPT_MUTATION_UNSUPPORTED_AFFINITIES:
        type_name = python_type_name_for_affinity(affinity)
        return f"'{type_name}' object does not support item assignment"
    return None
