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

"""UNPACK_SEQUENCE and UNPACK_EX handlers for assignment targets.

Resolves heap-backed containers, constrains symbolic lengths when known, and
forks or reports ``ValueError`` arity mismatches through exception handlers or
detectors. Star targets on non-concrete sequences use bounded list abstractions.
"""

from __future__ import annotations

import dis
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.scalars.values import fresh_name
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.helpers import (
    as_stack_value,
    extract_concrete_sequence,
    extract_length_expr,
    extract_none_expr,
    known_sequence_length,
    path_is_sat,
    require_stack_depth,
    resolve_heap_container,
    unpack_arity_error,
    unpack_value_at,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher

UNPACK_ITER_PROTOCOL = "__iter_unpack_sequence__"


@dataclass(frozen=True, slots=True)
class UnpackIterationContinuation:
    """Retained caller state for unpacking through a modeled ``__iter__`` call."""

    count: int
    unpack_pc: int
    continue_pc: int


def handle_common_unpack_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``UNPACK_SEQUENCE``: pop iterable and push ``count`` target values.

    Expands concrete sequences element-wise; symbolic iterables may introduce fresh
    names per slot or degrade when arity cannot be proved.
    """
    count = int(instr.argval) if instr.argval else 0
    require_stack_depth(state, instr, 1, "UNPACK_SEQUENCE source")
    container = resolve_heap_container(state, state.pop())

    literal_generator_items = _literal_generator_items(container)
    if literal_generator_items is not None:
        actual = len(literal_generator_items)
        if actual != count:
            return unpack_arity_error(instr, state, ctx, expected=count, actual=actual)
        for item in reversed(literal_generator_items):
            state = state.push(as_stack_value(item))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    iter_result = _dispatch_modeled_unpack_iter_protocol(state, ctx, container, count=count)
    if iter_result is not None:
        return iter_result

    known_len = known_sequence_length(container)
    if known_len is not None:
        if known_len != count:
            return unpack_arity_error(
                instr,
                state,
                ctx,
                expected=count,
                actual=known_len,
            )
        for i in reversed(range(count)):
            state = state.push(unpack_value_at(container, i))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    container_len = extract_length_expr(container)
    if container_len is not None:
        state = state.add_constraint(container_len == count)
    else:
        none_expr = extract_none_expr(container)
        can_be_none = container is None or (
            none_expr is not None and path_is_sat([*state.path_constraints, none_expr])
        )
        if not can_be_none:
            for i in reversed(range(count)):
                if isinstance(container, SymbolicList):
                    val = container[SymbolicValue.from_const(i)]
                else:
                    val, constraint = SymbolicValue.symbolic(f"unpack_{state.pc}_{i}")
                    state = state.add_constraint(constraint)
                state = state.push(val)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

        must_be_none = container is None or not path_is_sat(
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

    for i in reversed(range(count)):
        if isinstance(container, SymbolicList):
            val = container[SymbolicValue.from_const(i)]
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_{state.pc}_{i}")
            state = state.add_constraint(constraint)
        state = state.push(val)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _dispatch_modeled_unpack_iter_protocol(
    state: VMState,
    ctx: OpcodeDispatcher,
    container: StackValue,
    *,
    count: int,
) -> OpcodeResult | None:
    """Enter a modeled ``__iter__`` for native unpacking when the source defines one."""
    if not isinstance(container, SymbolicValue):
        return None
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    iter_method = lookup_modeled_method(container, "__iter__")
    if iter_method is None:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        iter_method,
        [],
        {},
        protocol_method=UNPACK_ITER_PROTOCOL,
        resume_pc=state.pc,
        protocol_retained_operand=cast(
            "StackValue",
            UnpackIterationContinuation(
                count=count,
                unpack_pc=state.pc,
                continue_pc=state.pc + 1,
            ),
        ),
    )
    return result


def complete_retained_unpack_iter(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult | None:
    """Complete an unpack suspended around a modeled ``__iter__`` return."""
    retained = _retained_unpack_iter(frame)
    if retained is None:
        return None
    state.depth -= 1
    if return_value is None:
        state = state.push(cast("StackValue", None)).set_pc(retained.unpack_pc)
        return OpcodeResult.continue_with(state)

    items = _exact_unpack_iter_items(return_value, state)
    if items is None:
        state = state.push(return_value).set_pc(retained.unpack_pc)
        return OpcodeResult.continue_with(state)

    actual = len(items)
    if actual != retained.count:
        instr = ctx.get_instruction(retained.unpack_pc)
        if not isinstance(instr, dis.Instruction):
            return OpcodeResult.terminate()
        return unpack_arity_error(instr, state, ctx, expected=retained.count, actual=actual)

    for item in reversed(items):
        state = state.push(item)
    return OpcodeResult.continue_with(state.set_pc(retained.continue_pc))


def _retained_unpack_iter(frame: CallFrame) -> UnpackIterationContinuation | None:
    """Return retained unpack state when this frame owns an unpack ``__iter__`` call."""
    if frame.protocol_method != UNPACK_ITER_PROTOCOL:
        return None
    retained = frame.protocol_retained_operand
    if isinstance(retained, UnpackIterationContinuation):
        return retained
    return None


def _exact_unpack_iter_items(
    return_value: StackValue,
    state: VMState,
) -> list[StackValue] | None:
    """Return exact finite items from an unpack ``__iter__`` return, if known."""
    from pysymex.models.builtins.core.iterator_items import concrete_iterable_items

    if isinstance(return_value, SymbolicIterator):
        return concrete_iterable_items(return_value, state)
    return concrete_iterable_items(return_value, state)


def _literal_generator_items(container: object) -> tuple[object, ...] | None:
    """Return simple literal generator yields, when the generator body is fully known."""
    from pysymex.execution.opcodes.common.generators import (
        ModeledGenerator,
        literal_generator_yields,
    )

    if not isinstance(container, ModeledGenerator):
        return None
    return literal_generator_yields(container)


def handle_common_unpack_ex(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unpack with starred target."""
    require_stack_depth(state, instr, 1, "UNPACK_EX source")
    container = resolve_heap_container(state, state.pop())
    arg = int(instr.argval) if instr.argval else 0
    before = arg & 0xFF
    after = (arg >> 8) & 0xFF

    sequence = extract_concrete_sequence(container)
    if sequence is not None:
        actual = len(sequence)
        required = before + after
        if actual < required:
            return unpack_arity_error(instr, state, ctx, expected=required, actual=actual)

        output_values: list[StackValue] = []
        output_values.extend(as_stack_value(item) for item in sequence[:before])
        star_stop = actual - after if after else actual
        output_values.append([as_stack_value(item) for item in sequence[before:star_stop]])
        if after:
            output_values.extend(as_stack_value(item) for item in sequence[-after:])

        for value in reversed(output_values):
            state = state.push(value)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    output_values: list[StackValue] = []
    for i in range(before):
        if isinstance(container, SymbolicList):
            val = container[SymbolicValue.from_const(i)]
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_ex_{state.pc}_before_{i}")
            state = state.add_constraint(constraint)
        output_values.append(val)
    if isinstance(container, SymbolicList):
        required = get_int_val(before + after)
        star_idx = z3.Int(fresh_name("unpack_ex_star_idx"))
        star_array = cast(
            "z3.ArrayRef",
            z3.Lambda(
                [star_idx],
                z3.Select(container.z3_array, star_idx + get_int_val(before)),
            ),
        )
        star = SymbolicList(
            _name=f"unpack_ex_{state.pc}_star",
            z3_array=star_array,
            z3_len=container.z3_len - required,
            element_type=container.element_type,
        )
        state = state.add_constraint(container.z3_len >= required)
        state = state.add_constraint(star.z3_len >= 0)
    else:
        star, star_constraint = SymbolicList.symbolic(f"unpack_ex_{state.pc}_star")
        state = state.add_constraint(star_constraint)
        container_len = extract_length_expr(container)
        if container_len is not None:
            required = get_int_val(before + after)
            star.z3_len = container_len - required
            state = state.add_constraint(container_len >= required)
            state = state.add_constraint(star.z3_len >= 0)
    output_values.append(star)
    for i in range(after):
        if isinstance(container, SymbolicList):
            item_index = container.z3_len - get_int_val(after - i)
            val = SymbolicValue(
                _name=f"unpack_ex_{state.pc}_after_{i}",
                z3_int=cast("z3.ArithRef", z3.Select(container.z3_array, item_index)),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
            )
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_ex_{state.pc}_after_{i}")
            state = state.add_constraint(constraint)
        output_values.append(val)
    for value in reversed(output_values):
        state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
