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

"""Detector issue publication, deferral, and suppression routing."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.publication.context.manager import (
    should_defer_dynamic_with_issue,
    should_replace_dynamic_exit_issue,
)
from pysymex._internal.execution.detectors.records import DeferredDetectorIssue
from pysymex._internal.execution.detectors.suppression.policy import (
    exception_handler_catches_issue,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.contract import Detector
    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.detectors.invocation.types import DetectorRunContext
    from pysymex._internal.execution.detectors.publication.types import DetectorSiteKey

logger = get_logger(__name__)


def record_detector_issue(
    *,
    context: DetectorRunContext,
    detector: Detector,
    issue: Issue,
    site_key: DetectorSiteKey,
    state: VMState,
    instr: dis.Instruction,
    active_instructions: list[dis.Instruction],
) -> None:
    """Publish, defer, or suppress one detector issue for the current step."""
    issue = _with_call_stack_trace(issue, state)
    if issue.detector_name is None:
        issue = replace(issue, detector_name=detector.name)
    replaces_dynamic_exit_issue = should_replace_dynamic_exit_issue(state)
    if exception_handler_catches_issue(context.dispatcher, issue, instr, state):
        if replaces_dynamic_exit_issue:
            state.deferred_detector_issues = []
            state.invalidate_cached_hash()
        context.session.suppressed_detector_offsets.add(instr.offset)
        return
    line_no = context.resolve_line_number(state.pc, active_instructions)
    column = _instruction_column(instr)
    if line_no != issue.line_number or (issue.column is None and column is not None):
        issue = replace(issue, line_number=line_no, column=issue.column or column)
    if replaces_dynamic_exit_issue:
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


def _with_call_stack_trace(issue: Issue, state: VMState) -> Issue:
    """Attach interprocedural call-stack evidence without overriding issue scope."""
    if issue.stack_trace or not state.call_stack:
        return issue
    return replace(issue, stack_trace=tuple(frame.function_name for frame in state.call_stack))


def _instruction_column(instr: dis.Instruction) -> int | None:
    """Return the source column for an instruction when CPython exposes one."""
    positions = getattr(instr, "positions", None)
    column = getattr(positions, "col_offset", None)
    return column if isinstance(column, int) else None
