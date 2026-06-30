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

"""Deferred detector issue routing and final publication."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.publication.tokens import (
    detector_issue_payload,
    detector_site_key,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.core.state.deferred import DeferredStateIssue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.detectors.publication.types import HookMap
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.execution.session.state.core import ExecutionSession

logger = get_logger(__name__)


def route_deferred_detector_issues(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    state: VMState,
) -> None:
    """Forward session-level deferred issues to a successor state or publish them.

    Drains ``session.deferred_detector_issues`` and checks each successor state
    in ``result.new_states`` for the ``PUSH_EXC_INFO / WITH_EXCEPT_START`` pair
    that indicates a ``with``-block exception-handler path. Issues are attached
    to the first matching successor state so the context manager's ``__exit__``
    can decide whether to suppress them.
    """
    deferred = session.deferred_detector_issues
    session.deferred_detector_issues = []
    if not deferred:
        return
    routed = False
    for next_state in result.new_states:
        instructions = next_state.current_instructions
        if instructions is None or next_state.pc + 1 >= len(instructions):
            continue
        first = instructions[next_state.pc]
        second = instructions[next_state.pc + 1]
        if (
            getattr(first, "opname", "") == "PUSH_EXC_INFO"
            and getattr(second, "opname", "") == "WITH_EXCEPT_START"
        ):
            next_state.deferred_detector_issues.extend(deferred)
            next_state.invalidate_cached_hash()
            routed = True
    if not routed:
        for pending in deferred:
            publish_deferred_issue(
                session=session,
                hook_owner=hook_owner,
                hooks=hooks,
                state=state,
                deferred=pending,
            )


def publish_deferred_issue(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    state: VMState,
    deferred: DeferredStateIssue,
) -> None:
    """Publish a deferred detector issue if its site has not already been reported."""
    site_key = detector_site_key(deferred)
    if site_key in session.reported_detector_sites:
        return
    issue = detector_issue_payload(deferred)
    session.reported_detector_sites.add(site_key)
    session.issues.append(issue)
    for hook in hooks.get("on_issue", ()):
        try:
            hook(hook_owner, state, issue)
        except Exception:
            logger.exception("Plugin hook execution failed")


def record_suppressed_dynamic_issues(
    *,
    session: ExecutionSession,
    result: OpcodeResult,
) -> None:
    """Record bytecode offsets for detector issues suppressed by successful ``__exit__``."""
    for next_state in result.new_states:
        if not next_state.deferred_detector_issues:
            continue
        instructions = next_state.current_instructions
        if instructions is None or next_state.pc < 0 or next_state.pc >= len(instructions):
            continue
        if getattr(instructions[next_state.pc], "opname", "") == "RERAISE":
            continue
        for deferred in next_state.deferred_detector_issues:
            issue_pc = detector_site_key(deferred)[1]
            if not 0 <= issue_pc < len(instructions):
                continue
            issue_instruction = instructions[issue_pc]
            if isinstance(issue_instruction, dis.Instruction):
                session.suppressed_detector_offsets.add(issue_instruction.offset)
