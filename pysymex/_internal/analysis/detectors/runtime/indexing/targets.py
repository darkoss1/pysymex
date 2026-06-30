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

"""Access-target extraction for index-error detector queries."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.calls import extract_argc, resolve_call_target_name
from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.analysis.detectors.runtime.indexing.bounds.evidence import (
    unwrap_symbolic_sequence,
)
from pysymex._internal.core.bytecode import DIRECT_CALL_OPCODES
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.guards import RuntimeObjectGuards

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState

CALL_OPCODES = DIRECT_CALL_OPCODES


def index_access_target(
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
) -> tuple[object, object] | Issue | None:
    """Return the container/index pair or direct pop issue for an index operation."""
    if instruction.opname in {"BINARY_SUBSCR", "DELETE_SUBSCR"}:
        if len(state.stack) < 2:
            return None
        return state.stack[-2], state.stack[-1]
    if instruction.opname not in CALL_OPCODES:
        return None
    return _pop_call_target(state, instruction, solver_check)


def resolve_memory_object(state: VMState, container: object) -> object:
    """Resolve heap-backed symbolic object containers when available."""
    if not isinstance(container, SymbolicObject) or container.address == -1:
        return container
    mem_obj = state.memory.get(container.address)
    if mem_obj is None:
        return container
    return mem_obj


def has_precise_index_bounds(container: object) -> bool:
    """Return whether pure bounds checking already covers the container."""
    unwrapped = unwrap_symbolic_sequence(container)
    return (
        isinstance(
            unwrapped,
            (SymbolicList, SymbolicTuple, SymbolicString, str, bytes, bytearray, range),
        )
        or RuntimeObjectGuards.list(unwrapped)
        or RuntimeObjectGuards.tuple(unwrapped)
    )


def _pop_call_target(
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
) -> tuple[object, object] | Issue | None:
    """Return the target for supported list-like pop calls."""
    argc = extract_argc(instruction)
    target_name = resolve_call_target_name(state, argc)
    if target_name is None:
        return None
    if not target_name.lower().endswith(".pop") and target_name.lower() != "pop":
        return None
    if argc == 0:
        if len(state.stack) < 2:
            return None
        container = resolve_memory_object(state, state.stack[-1])
        return _check_empty_default_pop(state, container, solver_check)
    if argc != 1 or len(state.stack) < argc + 2:
        return None
    return state.stack[-(argc + 1)], state.stack[-argc]


def _check_empty_default_pop(
    state: VMState,
    container: object,
    is_satisfiable_fn: IsSatFn,
) -> Issue | None:
    """Check whether ``container.pop()`` can raise ``IndexError`` on an empty sequence."""
    empty_condition = _empty_pop_condition(container)
    if empty_condition is None:
        return None
    container_name, can_be_empty = empty_condition
    can_be_empty = simplify_expr(can_be_empty)
    if z3.is_false(can_be_empty):
        return None
    constraints = list(state.path_constraints)
    if not z3.is_true(can_be_empty):
        constraints.append(can_be_empty)
    model = None
    if constraints:
        model = get_model_if_satisfiable_result(constraints, is_satisfiable_fn).model
        if model is None:
            return None
    return Issue(
        kind=IssueKind.INDEX_ERROR,
        message=f"Possible IndexError: pop from empty {container_name}",
        constraints=constraints,
        model=model,
        pc=state.pc,
    )


def _empty_pop_condition(container: object) -> tuple[str, z3.BoolRef] | None:
    """Return the empty-sequence condition for containers that support no-arg ``pop``."""
    unwrapped = unwrap_symbolic_sequence(container)
    if isinstance(unwrapped, SymbolicList):
        return unwrapped.name, unwrapped.z3_len == 0
    if RuntimeObjectGuards.list(unwrapped):
        return "list", Z3_TRUE if len(unwrapped) == 0 else Z3_FALSE
    if isinstance(unwrapped, bytearray):
        return "bytearray", Z3_TRUE if len(unwrapped) == 0 else Z3_FALSE
    return None
