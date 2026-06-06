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

"""Loop-bound and widening handoff policy for execution scheduling."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sized
from dataclasses import dataclass
import dis
from typing import cast

import z3

from pysymex.core.bytecode import instruction_stream_key
from pysymex.config.defaults import DEFAULT_LIMIT_MAX_LIST_LENGTH
from pysymex.logger import get_logger

from pysymex.analysis.static.loops.detector import LoopDetector
from pysymex.analysis.static.loops.types import LoopInfo
from pysymex.core.state.record import VMState
from pysymex.core.state.types import LoopCounterKey
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.execution.session.state import ExecutionSession

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class LoopBoundContext:
    """Mutable execution owners and policy values needed for loop-bound handling."""

    session: ExecutionSession
    max_loop_iterations: int
    verbose: bool
    record_path_explored_event: Callable[[], None]


def apply_loop_bound_policy(
    context: LoopBoundContext,
    state: VMState,
    active_instructions: list[dis.Instruction],
) -> bool:
    """Apply bounded loop exploration and optional widening to one scheduled state."""
    if state.pc >= len(active_instructions):
        return True

    loop_detector = _loop_detector_for_stream(context.session, active_instructions)
    if loop_detector is None:
        return True

    instr_offset = active_instructions[state.pc].offset
    loop = loop_detector.get_loop_at(instr_offset)

    if loop is None or not loop.is_header(instr_offset):
        return True

    pc_key = _loop_iteration_key(active_instructions, loop.header_pc)
    iteration_count = state.increment_loop_iteration(pc_key)
    max_loop_iterations = _effective_max_loop_iterations(context, state)

    if iteration_count > max_loop_iterations:
        if _try_widen_loop_state(context, state, active_instructions, loop, pc_key):
            return False

        if context.verbose:
            logger.debug("Loop at PC %s exceeded max iterations", pc_key)
        context.session.paths_pruned += 1
        return False

    state.prev_loop_states[pc_key] = state.fork()
    return True


def _loop_detector_for_stream(
    session: ExecutionSession,
    active_instructions: list[dis.Instruction],
) -> LoopDetector | None:
    """Return loop metadata for the active instruction stream when analysis is enabled."""
    if session.loop_detector is None:
        return None

    stream_key = instruction_stream_key(active_instructions)
    detector = session.loop_detectors.get(stream_key)
    if detector is not None:
        return detector

    detector = LoopDetector()
    detector.analyze_cfg(active_instructions)
    session.loop_detectors[stream_key] = detector
    return detector


def _loop_iteration_key(
    active_instructions: list[dis.Instruction],
    header_pc: int,
) -> LoopCounterKey:
    """Return the per-stream loop counter key for a bytecode loop header."""
    return (*instruction_stream_key(active_instructions), header_pc)


def _effective_max_loop_iterations(context: LoopBoundContext, state: VMState) -> int:
    """Return the loop cap after accounting for finite modeled iterators."""
    finite_length = _finite_iterator_length(state)
    if finite_length is None or finite_length < 0:
        return context.max_loop_iterations
    if finite_length > DEFAULT_LIMIT_MAX_LIST_LENGTH:
        return context.max_loop_iterations
    return max(context.max_loop_iterations, finite_length + 1)


def _finite_iterator_length(state: VMState) -> int | None:
    """Return a finite length for the active iterator when one is known cheaply."""
    if not state.stack:
        return None
    iterator = state.stack[-1]
    if not isinstance(iterator, SymbolicIterator):
        return None
    iterable = iterator.iterable
    if isinstance(iterable, SymbolicList):
        concrete_items = iterable.concrete_items
        if concrete_items is not None:
            return len(concrete_items)
        return _exact_int_value(iterable.z3_len, state.path_constraints)
    if isinstance(iterable, SymbolicString):
        return _exact_int_value(iterable.z3_len, state.path_constraints)
    if isinstance(iterable, Sized):
        return len(iterable)
    return None


def _exact_int_value(expr: z3.ArithRef, constraints: Iterable[z3.BoolRef]) -> int | None:
    """Return a concrete integer value implied by direct equality constraints."""
    simplified = z3.simplify(expr)
    if z3.is_int_value(simplified):
        return simplified.as_long()

    known: dict[int, int] = {}
    aliases: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for constraint in _iter_conjuncts(constraints):
        constraint = z3.simplify(constraint)
        if not z3.is_eq(constraint):
            continue
        left, right = constraint.children()
        left_simplified = z3.simplify(left)
        right_simplified = z3.simplify(right)
        if z3.is_int_value(left_simplified):
            known[right.hash()] = left_simplified.as_long()
        elif z3.is_int_value(right_simplified):
            known[left.hash()] = right_simplified.as_long()
        else:
            aliases.append((left, right))

    for _ in range(len(aliases) + 1):
        changed = False
        for left, right in aliases:
            left_hash = left.hash()
            right_hash = right.hash()
            if left_hash in known and right_hash not in known:
                known[right_hash] = known[left_hash]
                changed = True
            elif right_hash in known and left_hash not in known:
                known[left_hash] = known[right_hash]
                changed = True
        if not changed:
            break
    return known.get(expr.hash())


def _iter_conjuncts(constraints: Iterable[z3.BoolRef]) -> Iterator[z3.BoolRef]:
    """Yield top-level conjuncts from path constraints."""
    pending: list[z3.BoolRef] = list(constraints)
    while pending:
        constraint = pending.pop()
        if z3.is_and(constraint):
            pending.extend(cast("list[z3.BoolRef]", constraint.children()))
            continue
        yield constraint


def _try_widen_loop_state(
    context: LoopBoundContext,
    state: VMState,
    active_instructions: list[dis.Instruction],
    loop: LoopInfo,
    pc_key: LoopCounterKey,
) -> bool:
    widening = context.session.loop_widening
    if widening is None or not widening.should_widen(loop, state.loop_iterations[pc_key]):
        return False

    prev_state = state.prev_loop_states.get(pc_key)
    if prev_state is None or not loop.exit_pcs:
        return False

    widened = widening.widen_state(prev_state, state, loop)
    max_body_offset = max(loop.body_pcs) if loop.body_pcs else loop.header_pc
    exit_idx = _resolve_loop_exit_index(
        active_instructions=active_instructions,
        loop=loop,
        max_body_offset=max_body_offset,
    )
    if exit_idx is not None:
        widened = widened.set_pc(exit_idx)
    else:
        widened = widened.set_pc(len(active_instructions))

    _unwind_loop_blocks(widened, loop, max_body_offset)
    if context.session.worklist:
        context.session.worklist.add_state(widened)
    context.session.paths_explored += 1
    context.record_path_explored_event()
    if context.verbose:
        logger.debug("Loop at PC %s: widened and jumped to exit", pc_key)
    context.session.paths_pruned += 1
    return True


def _resolve_loop_exit_index(
    *,
    active_instructions: list[dis.Instruction],
    loop: LoopInfo,
    max_body_offset: int,
) -> int | None:
    for idx, instruction in enumerate(active_instructions):
        if instruction.offset > max_body_offset:
            return idx

    for exit_pc in sorted(loop.exit_pcs):
        for idx, instruction in enumerate(active_instructions):
            if instruction.offset == exit_pc:
                return idx
    return None


def _unwind_loop_blocks(widened: VMState, loop: LoopInfo, max_body_offset: int) -> None:
    while widened.block_stack:
        top_block = widened.block_stack[-1]
        if top_block.start_pc >= loop.header_pc and top_block.end_pc <= max_body_offset + 1:
            widened.exit_block()
        else:
            break
