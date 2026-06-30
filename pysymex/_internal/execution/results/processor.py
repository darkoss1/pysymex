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

"""Opcode-result processing for one executed instruction."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.publication.routing import (
    record_suppressed_dynamic_issues,
    route_deferred_detector_issues,
)
from pysymex._internal.execution.results.routing.fallbacks import (
    emit_opcode_result_fallback_events,
)
from pysymex._internal.execution.results.routing.issues import publish_opcode_result_issues
from pysymex._internal.execution.results.routing.successors import route_successor_opcode_result
from pysymex._internal.execution.results.routing.terminal import route_terminal_opcode_result

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.execution.results.context import ProcessingContext


def process_execution_result(
    context: ProcessingContext,
    result: OpcodeResult,
    state: VMState,
    active_instructions: list[dis.Instruction],
) -> None:
    """Route a single opcode result into session issues, snapshots, and worklist."""
    process_start = time.perf_counter()
    context.session.phase_counts["process_execution_result"] += 1
    try:
        context.session.record_degraded_passes(result.degraded_passes)
        emit_opcode_result_fallback_events(session=context.session, result=result)
        route_deferred_detector_issues(
            session=context.session,
            hook_owner=context.hook_owner,
            hooks=context.hooks,
            result=result,
            state=state,
        )
        record_suppressed_dynamic_issues(session=context.session, result=result)
        publish_opcode_result_issues(
            session=context.session,
            hook_owner=context.hook_owner,
            hooks=context.hooks,
            result=result,
            state=state,
            resolve_line_number=lambda pc: context.resolve_line_number(
                pc,
                active_instructions,
            ),
        )

        if route_terminal_opcode_result(
            session=context.session,
            hook_owner=context.hook_owner,
            hooks=context.hooks,
            result=result,
            state=state,
            on_path_complete=context.on_path_complete,
        ):
            return

        route_successor_opcode_result(
            session=context.session,
            hook_owner=context.hook_owner,
            hooks=context.hooks,
            result=result,
            state=state,
            resource_tracker=context.resource_tracker,
            record_path_explored=context.record_path_explored,
        )
    finally:
        context.session.phase_timers_seconds["process_execution_result"] += (
            time.perf_counter() - process_start
        )
