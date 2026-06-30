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

"""Result assembly helpers for function-return opcode handlers.

Owns return-path issue attachment, independently routed result merging, and degraded
protocol return events. The public opcode handlers still decide when these helpers apply.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.calls.construction_fallbacks import (
    construction_return_fallback_events,
)
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.protocol.fallbacks import (
    protocol_return_fallback_events,
)

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState


def combine_return_results(primary: OpcodeResult, secondary: OpcodeResult | None) -> OpcodeResult:
    """Merge an independently routed return-contract exception branch."""
    if secondary is None:
        return primary
    degraded_passes = list(dict.fromkeys([*primary.degraded_passes, *secondary.degraded_passes]))
    return OpcodeResult(
        new_states=[*primary.new_states, *secondary.new_states],
        issues=[*primary.issues, *secondary.issues],
        degraded_passes=degraded_passes,
        fallback_events=[*primary.fallback_events, *secondary.fallback_events],
        terminal=primary.terminal and secondary.terminal,
    )


def with_return_issues(result: OpcodeResult, issues: list[Issue]) -> OpcodeResult:
    """Attach contract-return issues without changing successor control flow."""
    if not issues:
        return result
    return OpcodeResult(
        new_states=result.new_states,
        issues=[*issues, *result.issues],
        degraded_passes=result.degraded_passes,
        fallback_events=result.fallback_events,
        terminal=result.terminal,
    )


def degraded_protocol_return_result(state: VMState, degraded_pass: str) -> OpcodeResult:
    """Return a terminal protocol-degradation result with specific event metadata."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[degraded_pass],
        fallback_events=[
            *construction_return_fallback_events(
                state=state,
                degraded_pass=degraded_pass,
            ),
            *protocol_return_fallback_events(
                state=state,
                degraded_pass=degraded_pass,
            ),
        ],
        terminal=True,
    )
