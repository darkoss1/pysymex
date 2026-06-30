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

"""UNPACK_SEQUENCE source resolution and arity semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.capabilities import known_sequence_length, length_expr, none_expr
from pysymex._internal.core.types.concrete_extraction import ConcreteExtractionPolicy
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
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
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.collections.unpack.protocol import (
    route_modeled_unpack_iter,
)
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability


if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.fallback.types import FallbackEvent
    from pysymex._internal.typing.protocols import StackValue


def _path_satisfiability_result(
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> SolverResult:
    return PathSatisfiability.result(constraints, known_sat_prefix_len=known_sat_prefix_len)


UNPACK_NONE_FEASIBILITY_UNKNOWN = "unpack_none_feasibility_unknown"
_UNPACK_NONE_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=UNPACK_NONE_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.collections",
    subject="UNPACK_SEQUENCE None/non-None",
)


def _push_reversed_values(state: VMState, values: tuple[object, ...]) -> VMState:
    """Push unpacked concrete values in CPython stack order."""
    for item in reversed(values):
        state = state.push(StackValuePolicy.coerce(item))
    return state


def _concrete_unpack_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    values: tuple[object, ...],
    *,
    expected: int,
) -> OpcodeResult:
    """Return a concrete-sequence unpack result or arity error."""
    actual = len(values)
    if actual != expected:
        return CollectionStackOps.unpack_arity_error(
            instr,
            state,
            ctx,
            expected=expected,
            actual=actual,
        )
    state = _push_reversed_values(state, values)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _push_symbolic_unpack_values(
    state: VMState,
    container: object,
    count: int,
) -> VMState:
    """Push symbolic/fallback unpack values for an imprecise container."""
    for i in reversed(range(count)):
        if isinstance(container, SymbolicList):
            val = container[SymbolicValue.from_const(i)]
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_{state.pc}_{i}")
            state = state.add_constraint(constraint)
        state = state.push(val)
    return state


def _unpack_none_fallback_events(
    state: VMState,
    container: object,
) -> tuple[list[FallbackEvent], bool, z3.BoolRef | None]:
    """Return fallback events plus whether the container may still be non-None."""
    container_none_expr = none_expr(container)
    none_result = None
    non_none_result = None
    if container_none_expr is not None:
        none_result = _path_satisfiability_result(
            [*state.path_constraints, container_none_expr],
            known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
        )
    can_be_none = container is None or (none_result is not None and may_be_feasible(none_result))
    if not can_be_none:
        return [], False, container_none_expr
    if container_none_expr is not None:
        non_none_result = _path_satisfiability_result(
            [*state.path_constraints, z3.Not(container_none_expr)],
            known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
        )
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_UNPACK_NONE_FEASIBILITY_SPEC,
        branches=[
            *([] if none_result is None else [FeasibilityBranch("none", none_result)]),
            *([] if non_none_result is None else [FeasibilityBranch("non_none", non_none_result)]),
        ],
    )
    must_be_none = container is None or (
        non_none_result is not None and not may_be_feasible(non_none_result)
    )
    is_unconstrained_var = (
        container_none_expr is not None
        and z3.is_const(container_none_expr)
        and container_none_expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
    )
    if must_be_none or not is_unconstrained_var:
        return fallback_events, must_be_none, container_none_expr
    return fallback_events, False, container_none_expr


def handle_common_unpack_sequence(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``UNPACK_SEQUENCE``: pop iterable and push ``count`` target values."""
    count = int(instr.argval) if instr.argval else 0
    CollectionStackOps.require_depth(state, instr, 1, "UNPACK_SEQUENCE source")
    container = SymbolicObject.resolve_stack_value(state, state.pop())

    literal_generator_items = _literal_generator_items(container)
    if literal_generator_items is not None:
        return _concrete_unpack_result(
            instr,
            state,
            ctx,
            literal_generator_items,
            expected=count,
        )

    concrete_sequence = ConcreteExtractionPolicy.sequence(container)
    if concrete_sequence is not None:
        return _concrete_unpack_result(
            instr,
            state,
            ctx,
            tuple(concrete_sequence),
            expected=count,
        )

    stack_container = cast("StackValue", container)
    iter_result = route_modeled_unpack_iter(state, ctx, stack_container, count=count)
    if iter_result is not None:
        return iter_result

    known_len = known_sequence_length(container)
    if known_len is not None:
        if known_len != count:
            return CollectionStackOps.unpack_arity_error(
                instr,
                state,
                ctx,
                expected=count,
                actual=known_len,
            )
        state = _push_symbolic_unpack_values(state, stack_container, count)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    container_len = length_expr(container)
    fallback_events: list[FallbackEvent] = []
    if container_len is not None:
        state = state.add_constraint(container_len == count)
    else:
        fallback_events, must_be_none, container_none_expr = _unpack_none_fallback_events(
            state,
            container,
        )
        if not fallback_events and container_none_expr is not None:
            state = _push_symbolic_unpack_values(state, container, count)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
        if must_be_none:
            state = state.advance_pc()
            return append_fallback_events(OpcodeResult.continue_with(state), fallback_events)
        if container_none_expr is not None:
            state = state.add_constraint(z3.Not(container_none_expr))

    state = _push_symbolic_unpack_values(state, container, count)
    state = state.advance_pc()
    return append_fallback_events(OpcodeResult.continue_with(state), fallback_events)


def _literal_generator_items(container: object) -> tuple[object, ...] | None:
    """Return simple literal generator yields, when the generator body is fully known."""
    from pysymex._internal.core.types.containers.generators import ModeledGenerator
    from pysymex._internal.execution.opcodes.common.generators.literals import (
        literal_generator_yields,
    )

    if not isinstance(container, ModeledGenerator):
        return None
    return literal_generator_yields(container)
