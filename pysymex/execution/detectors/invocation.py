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

"""Per-instruction detector invocation and issue publication policy."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
import dis
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors import Detector, Issue, IssueKind
from pysymex.core.state.record import VMState
from pysymex.execution.detectors import DeferredDetectorIssue, DetectorQueryContext
from pysymex.execution.detectors.publication import (
    should_defer_dynamic_with_issue,
    should_replace_dynamic_exit_issue,
)
from pysymex.execution.detectors.query.cache import detector_query_is_sat
from pysymex.execution.detectors.suppression import issue_is_caught_by_exception_handler
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.execution.session.state import ExecutionSession
    from pysymex.typing import SolverProtocol

__all__ = [
    "DetectorRunContext",
    "run_detectors",
]

HookMap = Mapping[str, Sequence[Callable[..., object]]]
ResolveLineNumber = Callable[[int, list[dis.Instruction]], int | None]

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class DetectorRunContext:
    """Runtime owners needed to run detectors for one instruction."""

    session: ExecutionSession
    solver: SolverProtocol
    dispatcher: OpcodeDispatcher
    hook_owner: object
    hooks: HookMap
    detector_dispatch: dict[str, list[Detector]]
    universal_detectors: list[Detector]
    resolve_line_number: ResolveLineNumber


def run_detectors(
    context: DetectorRunContext,
    state: VMState,
    instr: dis.Instruction,
    active_instructions: list[dis.Instruction],
) -> None:
    """Run enabled detectors for the current instruction and publish reportable issues."""
    context.session.deferred_detector_issues = []
    opname = instr.opname
    specific_detectors = context.detector_dispatch.get(opname)
    if not context.universal_detectors and not specific_detectors:
        return

    instruction_stream_id = id(active_instructions)
    for detector in context.universal_detectors:
        _run_detector(
            context=context,
            detector=detector,
            instruction_stream_id=instruction_stream_id,
            state=state,
            instr=instr,
            active_instructions=active_instructions,
        )

    if specific_detectors:
        for detector in specific_detectors:
            _run_detector(
                context=context,
                detector=detector,
                instruction_stream_id=instruction_stream_id,
                state=state,
                instr=instr,
                active_instructions=active_instructions,
            )


def _run_detector(
    *,
    context: DetectorRunContext,
    detector: Detector,
    instruction_stream_id: int,
    state: VMState,
    instr: dis.Instruction,
    active_instructions: list[dis.Instruction],
) -> None:
    """Run one detector unless this site was already reported."""
    site_key = (instruction_stream_id, state.pc, detector.issue_kind)
    if site_key in context.session.reported_detector_sites:
        return
    if logger.state.trace_enabled:
        logger.trace(
            "detector check name=%s path_id=%d pc=%d opname=%s",
            detector.name,
            state.path_id,
            state.pc,
            instr.opname,
        )

    def query_is_sat(constraints: list[z3.BoolRef]) -> bool:
        inconclusive_prefix = (
            tuple(state.path_constraints)
            if state.last_inconclusive_feasibility_len == len(state.path_constraints)
            else None
        )
        query_context = (
            _detector_query_context(
                context=context,
                detector=detector,
                state=state,
                instr=instr,
                active_instructions=active_instructions,
            )
            if context.session.detector_query_event_observers
            else None
        )
        return detector_query_is_sat(
            session=context.session,
            solver=context.solver,
            constraints=constraints,
            inconclusive_path_prefix=inconclusive_prefix,
            query_context=query_context,
        )

    issue = detector.check(state, instr, query_is_sat)
    if issue is not None:
        _record_detector_issue(
            context=context,
            detector=detector,
            issue=issue,
            site_key=site_key,
            state=state,
            instr=instr,
            active_instructions=active_instructions,
        )


def _record_detector_issue(
    *,
    context: DetectorRunContext,
    detector: Detector,
    issue: Issue,
    site_key: tuple[int, int, IssueKind],
    state: VMState,
    instr: dis.Instruction,
    active_instructions: list[dis.Instruction],
) -> None:
    """Publish, defer, or suppress one detector issue for the current step."""
    if issue_is_caught_by_exception_handler(context.dispatcher, issue, instr, state):
        context.session.suppressed_detector_offsets.add(instr.offset)
        return
    line_no = context.resolve_line_number(state.pc, active_instructions)
    if line_no != issue.line_number:
        issue = replace(issue, line_number=line_no)
    if should_replace_dynamic_exit_issue(state):
        state.deferred_detector_issues = [DeferredDetectorIssue(issue, site_key)]
        state.invalidate_cached_hash()
        return
    if should_defer_dynamic_with_issue(context.dispatcher, state, instr):
        context.session.deferred_detector_issues.append(DeferredDetectorIssue(issue, site_key))
        return
    context.session.reported_detector_sites.add(site_key)
    if logger.state.trace_enabled:
        logger.trace(
            "detector issue emitted name=%s kind=%s path_id=%d pc=%d",
            detector.name,
            issue.kind.value,
            state.path_id,
            state.pc,
        )
    context.session.issues.append(issue)
    for hook in context.hooks.get("on_issue", ()):
        try:
            hook(context.hook_owner, state, issue)
        except Exception:
            logger.exception("Plugin hook execution failed")


def _detector_query_context(
    *,
    context: DetectorRunContext,
    detector: Detector,
    state: VMState,
    instr: dis.Instruction,
    active_instructions: list[dis.Instruction],
) -> DetectorQueryContext:
    """Build bounded detector-query context for trace observers."""
    return DetectorQueryContext(
        detector_name=detector.name,
        issue_kind=detector.issue_kind.name,
        path_id=state.path_id,
        pc=state.pc,
        line_number=context.resolve_line_number(state.pc, active_instructions),
        opcode=instr.opname,
        state_constraints_count=len(state.path_constraints),
        pending_constraint_count=state.pending_constraint_count,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
    )
