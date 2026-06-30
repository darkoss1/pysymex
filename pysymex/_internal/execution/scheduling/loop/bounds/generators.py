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

"""Structural finite-yield proofs for modeled generator continuations."""

from __future__ import annotations

import dis

from pysymex._internal.core.calls.payload import function_payload
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.iterators import SymbolicIterator


def finite_generator_yield_upper_bound(generator: ModeledGenerator) -> int | None:
    """Return a yield-count upper bound when the generator bytecode is acyclic.

    Acyclic bytecode can visit every ``YIELD_VALUE`` at most once. Conditional
    branches may skip yields, so their total count is a sound upper bound. Any
    backward control-flow edge rejects the proof instead of guessing how often
    the generator body may repeat.
    """
    instructions = _generator_instructions(generator)
    if instructions is None or any(_is_backward_control_edge(item) for item in instructions):
        return None
    return sum(item.opname == "YIELD_VALUE" for item in instructions)


def generator_remaining_steps(
    previous: VMState,
    current: VMState,
) -> int | None:
    """Return a finite dynamic rank for one modeled generator continuation.

    Advancing to a later suspension point decreases the finite bytecode-position
    rank. A ``yield from`` suspension may remain at one instruction while its
    retained finite iterator advances, so that iterator supplies the nested
    rank. Both proofs are rechecked on every outer-loop traversal.
    """
    old = _active_generator(previous)
    new = _active_generator(current)
    if old is None or new is None or old.identity != new.identity:
        return None

    instructions = _generator_instructions(new)
    if instructions is None:
        return None
    old_resume = -1 if old.resume_pc is None else old.resume_pc
    new_resume = -1 if new.resume_pc is None else new.resume_pc
    if new_resume > old_resume:
        return sum(item.offset >= new_resume for item in instructions)
    if new_resume != old_resume:
        return None

    from pysymex._internal.execution.scheduling.loop.bounds.finite import (
        finite_iterator_upper_bound,
    )

    for old_value, new_value in zip(old.suspended_stack, new.suspended_stack, strict=False):
        if not isinstance(old_value, SymbolicIterator) or not isinstance(
            new_value,
            SymbolicIterator,
        ):
            continue
        if new_value.index <= old_value.index:
            continue
        upper_bound = finite_iterator_upper_bound(
            VMState(stack=[new_value], path_constraints=current.path_constraints),
        )
        if upper_bound is not None:
            return max(0, upper_bound - new_value.index)
    return None


def _generator_instructions(generator: ModeledGenerator) -> tuple[dis.Instruction, ...] | None:
    if generator.instructions:
        return generator.instructions
    payload = function_payload(generator.function)
    code = payload.code if payload is not None else getattr(generator.function, "__code__", None)
    if code is None:
        return None
    return tuple(dis.get_instructions(code))


def _active_generator(state: VMState) -> ModeledGenerator | None:
    if state.stack and isinstance(state.stack[-1], ModeledGenerator):
        return state.stack[-1]
    return None


def _is_backward_control_edge(instruction: dis.Instruction) -> bool:
    if instruction.opcode not in dis.hasjabs and instruction.opcode not in dis.hasjrel:
        return False
    target = instruction.argval
    return isinstance(target, int) and target <= instruction.offset
