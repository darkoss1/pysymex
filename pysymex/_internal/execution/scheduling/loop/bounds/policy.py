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

"""Loop-bound policy entrypoint."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.bytecode import instruction_stream_key
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)
from pysymex._internal.execution.resources.events import record_resource_limit_degradation
from pysymex._internal.execution.scheduling.loop.bounds.finite import (
    effective_max_loop_iterations,
    finite_countdown_remaining_steps,
    finite_iterator_upper_bound,
)
from pysymex._internal.execution.scheduling.loop.bounds.generators import (
    generator_remaining_steps,
)
from pysymex._internal.execution.scheduling.loop.bounds.ranking import (
    finite_container_descent_remaining_steps,
    guarded_affine_remaining_steps,
)
from pysymex._internal.execution.scheduling.loop.bounds.widening import try_widen_loop_state
from pysymex._internal.execution.scheduling.loops.detector import LoopDetector
from pysymex._internal.execution.strategies.merger.equality.coverage import (
    state_exactly_covers,
    state_payload_equal_except_locals,
)
from pysymex._internal.limits.models import LimitExceeded, ResourceType
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import LoopCounterKey
    from pysymex._internal.execution.scheduling.loop.bounds.context import LoopBoundContext
    from pysymex._internal.execution.scheduling.loops.types import LoopInfo
    from pysymex._internal.execution.session.state.core import ExecutionSession

logger = get_logger(__name__)

LOOP_WIDENING_DEGRADED_PASS = "loop_widening_precision_loss"
LOOP_CONVERGENCE_UNSUPPORTED = "loop_convergence_unsupported"


def apply_loop_bound_policy(
    context: LoopBoundContext,
    state: VMState,
    active_instructions: list[dis.Instruction],
) -> bool:
    """Apply bounded loop exploration and optional widening to one scheduled state."""
    if state.pc >= len(active_instructions):
        return True

    loop_detector = loop_detector_for_stream(context.session, active_instructions)
    if loop_detector is None:
        return True

    instr_offset = active_instructions[state.pc].offset
    loop = loop_detector.get_loop_at(instr_offset)

    if loop is None or not loop.is_header(instr_offset):
        return True

    pc_key = loop_iteration_key(active_instructions, loop.header_pc)
    iteration_count = state.increment_loop_iteration(pc_key)
    max_loop_iterations = effective_max_loop_iterations(context, state)

    if max_loop_iterations is not None and iteration_count > max_loop_iterations:
        _record_loop_bound_degradation(
            context=context,
            state=state,
            iteration_count=iteration_count,
            max_loop_iterations=max_loop_iterations,
        )
        _record_structural_infinite_loop_issue(
            context=context,
            state=state,
            active_instructions=active_instructions,
            loop=loop,
            max_loop_iterations=max_loop_iterations,
        )
        if try_widen_loop_state(
            context,
            state,
            active_instructions,
            loop,
            pc_key,
            require_progress_evidence=False,
        ):
            return False

        if context.verbose:
            logger.debug("Loop at PC %s exceeded max iterations", pc_key)
        context.session.paths_pruned += 1
        return False

    if max_loop_iterations is None:
        finite_length = finite_iterator_upper_bound(state)
        if finite_length is not None and finite_length >= 0:
            state.prev_loop_states[pc_key] = state.fork()
            return True
        return _apply_automatic_loop_policy(
            context=context,
            state=state,
            active_instructions=active_instructions,
            loop=loop,
            pc_key=pc_key,
            iteration_count=iteration_count,
        )

    state.prev_loop_states[pc_key] = state.fork()
    return True


def _apply_automatic_loop_policy(
    *,
    context: LoopBoundContext,
    state: VMState,
    active_instructions: list[dis.Instruction],
    loop: LoopInfo,
    pc_key: LoopCounterKey,
    iteration_count: int,
) -> bool:
    """Apply exact recurrence, structural termination, or explicit approximation."""
    prev_state = state.prev_loop_states.get(pc_key)
    if prev_state is None:
        state.prev_loop_states[pc_key] = state.fork()
        return True

    if state_exactly_covers(prev_state, state):
        _record_structural_infinite_loop_issue(
            context=context,
            state=state,
            active_instructions=active_instructions,
            loop=loop,
            max_loop_iterations=None,
        )
        context.session.paths_pruned += 1
        return False

    if finite_countdown_remaining_steps(prev_state, state) is not None:
        state.prev_loop_states[pc_key] = state.fork()
        return True

    if finite_container_descent_remaining_steps(prev_state, state) is not None:
        state.prev_loop_states[pc_key] = state.fork()
        return True

    if generator_remaining_steps(prev_state, state) is not None:
        state.prev_loop_states[pc_key] = state.fork()
        return True

    if (
        guarded_affine_remaining_steps(
            prev_state,
            state,
            active_instructions,
            loop,
        )
        is not None
    ):
        state.prev_loop_states[pc_key] = state.fork()
        return True

    if not loop.exit_pcs:
        _record_structural_infinite_loop_issue(
            context=context,
            state=state,
            active_instructions=active_instructions,
            loop=loop,
            max_loop_iterations=None,
        )
        context.session.paths_pruned += 1
        return False

    if state_payload_equal_except_locals(prev_state, state) and try_widen_loop_state(
        context,
        state,
        active_instructions,
        loop,
        pc_key,
    ):
        _record_loop_widening_degradation(context, state, iteration_count)
        return False

    _record_loop_convergence_unsupported(context, state, iteration_count)
    if context.continue_unsupported_with_host_guard:
        state.prev_loop_states[pc_key] = state.fork()
        return True
    context.session.paths_pruned += 1
    return False


def _record_structural_infinite_loop_issue(
    *,
    context: LoopBoundContext,
    state: VMState,
    active_instructions: list[dis.Instruction],
    loop: LoopInfo,
    max_loop_iterations: int | None,
) -> None:
    """Report loops with no modeled CFG exit when bounded exploration cuts them."""
    if loop.exit_pcs:
        return

    site_key = (id(active_instructions), state.pc, IssueKind.INFINITE_LOOP)
    if site_key in context.session.reported_detector_sites:
        return

    line_number = context.session.pc_to_line.get(state.pc)
    evidence = (
        f"exceeded {max_loop_iterations} iteration(s)"
        if max_loop_iterations is not None
        else "recurred after a completed body traversal"
    )
    issue = Issue(
        kind=IssueKind.INFINITE_LOOP,
        message=f"Potential infinite loop: loop has no modeled exit and {evidence}",
        constraints=list(state.path_constraints),
        pc=state.pc,
        line_number=line_number,
        confidence=0.8,
    )
    context.session.reported_detector_sites.add(site_key)
    context.session.issues.append(issue)


def _record_loop_widening_degradation(
    context: LoopBoundContext,
    state: VMState,
    iteration_count: int,
) -> None:
    """Record automatic loop widening as explicit precision loss."""
    context.session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.PRECISION_LOSS,
            label=LOOP_WIDENING_DEGRADED_PASS,
            owner="execution.scheduling.loop.bounds",
            reason=f"loop recurrence widened after {iteration_count} observed header visits",
            pc=state.pc,
            soundness=SoundnessTag.PRECISION_LOSS,
            false_positive_risk=RiskLevel.MEDIUM,
            false_negative_risk=RiskLevel.HIGH,
        ),
    )
    context.session.record_degraded_passes([LOOP_WIDENING_DEGRADED_PASS])


def _record_loop_convergence_unsupported(
    context: LoopBoundContext,
    state: VMState,
    iteration_count: int,
) -> None:
    """Record a recurrent state outside the current loop abstract domain."""
    context.session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.UNKNOWN,
            label=LOOP_CONVERGENCE_UNSUPPORTED,
            owner="execution.scheduling.loop.bounds",
            reason=(
                "loop recurrence changed stack, memory, globals, or frame state outside "
                f"local-variable widening after {iteration_count} header visits"
            ),
            pc=state.pc,
            soundness=SoundnessTag.INCONCLUSIVE,
            false_positive_risk=RiskLevel.LOW,
            false_negative_risk=RiskLevel.HIGH,
        ),
    )
    context.session.record_degraded_passes([LOOP_CONVERGENCE_UNSUPPORTED])


def _record_loop_bound_degradation(
    *,
    context: LoopBoundContext,
    state: VMState,
    iteration_count: int,
    max_loop_iterations: int,
) -> None:
    """Mark loop-bound pruning or widening as incomplete path exploration."""
    record_resource_limit_degradation(
        exc=LimitExceeded(
            ResourceType.ITERATIONS,
            iteration_count,
            max_loop_iterations,
        ),
        session=context.session,
        state=state,
        reason="loop iteration bound reached",
    )


def loop_detector_for_stream(
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


def loop_iteration_key(
    active_instructions: list[dis.Instruction],
    header_pc: int,
) -> LoopCounterKey:
    """Return the per-stream loop counter key for a bytecode loop header."""
    return (*instruction_stream_key(active_instructions), header_pc)
