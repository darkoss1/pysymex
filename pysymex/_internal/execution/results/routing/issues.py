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

"""Opcode-result issue publication and hook dispatch."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.publication.context.manager import (
    should_replace_dynamic_exit_issue,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.execution.results.routing.types import HookMap, LineNumberResolver
    from pysymex._internal.execution.session.state.core import ExecutionSession

logger = get_logger(__name__)


def publish_opcode_result_issues(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    state: VMState,
    resolve_line_number: LineNumberResolver,
) -> None:
    """Publish opcode-result issues to the session and issue hooks."""
    if result.issues and should_replace_dynamic_exit_issue(state):
        state.deferred_detector_issues = []
        state.invalidate_cached_hash()
    for issue in result.issues:
        line_no = (
            issue.line_number if issue.line_number is not None else resolve_line_number(issue.pc)
        )
        if issue.line_number is None and line_no != issue.line_number:
            issue = replace(issue, line_number=line_no)
        session.issues.append(issue)
        for hook in hooks.get("on_issue", ()):
            try:
                hook(hook_owner, state, issue)
            except Exception:
                logger.exception("Plugin hook execution failed")
