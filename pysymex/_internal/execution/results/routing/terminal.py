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

"""Terminal opcode-result routing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.publication.routing import publish_deferred_issue
from pysymex._internal.execution.step.snapshots import record_terminal_path
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.execution.results.routing.types import HookMap, PathCompleteCallback
    from pysymex._internal.execution.session.state.core import ExecutionSession

logger = get_logger(__name__)


def route_terminal_opcode_result(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    state: VMState,
    on_path_complete: PathCompleteCallback,
) -> bool:
    """Route terminal opcode results and return whether routing consumed the result."""
    if not result.terminal:
        return False

    if not result.degraded_passes:
        for deferred in state.deferred_detector_issues:
            publish_deferred_issue(
                session=session,
                hook_owner=hook_owner,
                hooks=hooks,
                state=state,
                deferred=deferred,
            )
    state.deferred_detector_issues = []
    state.invalidate_cached_hash()
    if logger.state.trace_enabled:
        logger.trace(
            "terminal path path_id=%d pc=%d issues=%d",
            state.path_id,
            state.pc,
            len(result.issues),
        )
    record_terminal_path(
        session=session,
        state=state,
        include_stack=True,
        final_exception=result.issues[0] if result.issues else None,
        update_exception=True,
    )
    on_path_complete(state)
    return True
