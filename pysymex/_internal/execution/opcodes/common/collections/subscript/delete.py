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

"""``DELETE_SUBSCR`` mutation paths for concrete and modeled containers."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.effects.locations import item_write_location
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.affinity import (
    SUBSCRIPT_MUTATION_UNSUPPORTED_AFFINITIES,
    python_type_name_for_affinity,
)
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.capabilities import symbolic_affinity
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.stack_coercion import StackValuePolicy
from pysymex._internal.execution.dispatch.result import OpcodeResult
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
    try_delete_retained_slice,
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

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_delete_subscr(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``DELETE_SUBSCR``: pop index and container and remove the item.

    Mirrors store paths for modeled containers; may branch to exception handlers when
    deletion can fail under symbolic indices.
    """
    CollectionStackOps.require_depth(state, instr, 2, "DELETE_SUBSCR container and key")
    key = state.pop()
    container = state.pop()
    write_location = item_write_location(state, container)
    modeled_result = route_modeled_subscript(state, ctx, container, "__delitem__", [key])
    if modeled_result is not None:
        return modeled_result
    real_container = container
    container_addr = -1
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container_addr, container)
    if isinstance(real_container, (list, SymbolicList)):
        slice_result = try_delete_retained_slice(
            instr,
            state,
            ctx,
            container,
            cast("object", real_container),
            container_addr,
            key,
        )
        if slice_result is not None:
            return slice_result
        index_result = route_modeled_index(state, ctx, [container], key)
        if index_result is not None:
            return index_result

    if isinstance(real_container, list):
        try:
            list_delitem = cast(
                "Callable[[StackValue], None]",
                cast("list[StackValue]", real_container).__delitem__,
            )
            list_delitem(key)
            state = record_item_write(state, write_location, instr)
        except TypeError as exc:
            return subscript_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)
        except IndexError as exc:
            return subscript_exception_result(instr, state, ctx, IssueKind.INDEX_ERROR, exc)

    elif isinstance(real_container, dict):
        try:
            del cast("dict[object, object]", real_container)[concrete_dict_key(key)]
            state = record_item_write(state, write_location, instr)
        except TypeError as exc:
            return subscript_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)
        except KeyError as exc:
            return subscript_exception_result(instr, state, ctx, IssueKind.KEY_ERROR, exc)

    elif isinstance(real_container, SymbolicString):
        return subscript_exception_result(
            instr,
            state,
            ctx,
            IssueKind.TYPE_ERROR,
            TypeError("'str' object doesn't support item deletion"),
        )

    elif isinstance(real_container, SymbolicDict):
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
                reason="DELETE_SUBSCR dict key requires symbolic or modeled object hashing",
            )

        mutation_key, storage_key = symbolic_dict_subscript_keys(key)
        state = state.add_constraint(real_container.contains_key(storage_key).z3_bool)
        new_container = real_container.__delitem__(mutation_key)
        if container_addr != -1:
            state = state.store_heap(container_addr, new_container)
            state = replace_direct_container_aliases(state, real_container, new_container)
        else:
            state = replace_direct_container_aliases(state, real_container, new_container)
        state = record_item_write(state, write_location, instr)
    elif isinstance(real_container, SymbolicList):
        symbolic_key = StackValuePolicy.as_index(key)
        if symbolic_key is not None:

            def apply_symbolic_list_delete(success_state: VMState) -> VMState:
                new_container = real_container.__delitem__(symbolic_key)
                if container_addr != -1:
                    success_state = success_state.store_heap(container_addr, new_container)
                    success_state = replace_direct_container_aliases(
                        success_state,
                        real_container,
                        new_container,
                    )
                else:
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
                apply_symbolic_list_delete,
            )
    else:
        type_error_message = _definite_delete_subscr_type_error(real_container)
        if type_error_message is not None:
            return subscript_exception_result(
                instr,
                state,
                ctx,
                IssueKind.TYPE_ERROR,
                TypeError(type_error_message),
            )

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _definite_delete_subscr_type_error(container: object) -> str | None:
    """Return a definite CPython ``DELETE_SUBSCR`` ``TypeError`` message, if any."""
    if container is None or isinstance(container, SymbolicNoneType):
        return "'NoneType' object does not support item deletion"
    if isinstance(container, (str, tuple, bytes)):
        type_name = type(cast("object", container)).__name__
        return f"'{type_name}' object doesn't support item deletion"
    if isinstance(container, (int, float, bool)):
        type_name = type(cast("object", container)).__name__
        return f"'{type_name}' object does not support item deletion"
    if isinstance(container, SymbolicValue):
        if z3.is_true(simplify_expr(container.is_none)):
            return "'NoneType' object does not support item deletion"
        if container.affinity_type in {"int", "float", "bool"}:
            return f"'{container.affinity_type}' object does not support item deletion"
        if container.affinity_type == "str" or z3.is_true(simplify_expr(container.is_str)):
            return "'str' object doesn't support item deletion"
    affinity = symbolic_affinity(container)
    if affinity in SUBSCRIPT_MUTATION_UNSUPPORTED_AFFINITIES:
        type_name = python_type_name_for_affinity(affinity)
        return f"'{type_name}' object does not support item deletion"
    return None
