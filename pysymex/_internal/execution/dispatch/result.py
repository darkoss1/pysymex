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

"""Opcode-step result data returned by dispatch handlers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.fallback.types import FallbackEvent


def _empty_degraded_passes() -> list[str]:
    """Create a typed empty degradation-marker list."""
    return []


def _empty_fallback_events() -> list[FallbackEvent]:
    """Create a typed empty fallback-event list."""
    return []


@dataclass
class OpcodeResult:
    """States, issues, degradation markers, and terminal status from one opcode.

    Attributes:
        new_states: Successor VM states returned for further exploration.
        issues: Issues emitted while handling this instruction.
        degraded_passes: Precision-loss or inconclusive-analysis markers.
        fallback_events: Structured internal fallback/degradation events.
        terminal: Whether this result ends the current execution path.

    """

    new_states: list[VMState]
    issues: list[Issue]
    degraded_passes: list[str] = field(default_factory=_empty_degraded_passes)
    terminal: bool = False
    fallback_events: list[FallbackEvent] = field(default_factory=_empty_fallback_events)

    @classmethod
    def continue_with(
        cls,
        state: VMState,
        degraded_passes: list[str] | None = None,
        fallback_events: list[FallbackEvent] | None = None,
    ) -> OpcodeResult:
        """Return a nonterminal result retaining one successor state.

        Args:
            state: The successor VMState to continue execution from.
            degraded_passes: Optional list of degradation reason strings if precision was lost.
            fallback_events: Optional structured fallback events for this opcode.

        Returns:
            An OpcodeResult configured to continue path exploration with the successor state.

        """
        return cls(
            new_states=[state],
            issues=[],
            degraded_passes=degraded_passes or [],
            fallback_events=fallback_events or [],
        )

    @classmethod
    def branch(
        cls,
        states: list[VMState],
        issues: list[Issue] | None = None,
        degraded_passes: list[str] | None = None,
        fallback_events: list[FallbackEvent] | None = None,
    ) -> OpcodeResult:
        """Return successor states with any issues attached to this result.

        Args:
            states: Successor VMStates resulting from a branch point.
            issues: Optional list of issues detected on this step.
            degraded_passes: Optional list of degradation reason strings if precision was lost.
            fallback_events: Optional structured fallback events for this opcode.

        Returns:
            An OpcodeResult containing the multiple successor states.

        """
        all_issues = list(issues) if issues is not None else []
        return cls(
            new_states=states,
            issues=all_issues,
            degraded_passes=degraded_passes or [],
            fallback_events=fallback_events or [],
        )

    @classmethod
    def fork(
        cls,
        states: list[VMState],
        issues: list[Issue | None],
        degraded_passes: list[str] | None = None,
        fallback_events: list[FallbackEvent] | None = None,
    ) -> OpcodeResult:
        """Return forked states while flattening non-``None`` issues into one list.

        Args:
            states: Forked successor VMStates.
            issues: List of issues to associate with the states, filtering out None.
            degraded_passes: Optional list of degradation reason strings if precision was lost.
            fallback_events: Optional structured fallback events for this opcode.

        Returns:
            An OpcodeResult containing successor states and flattened issues.

        """
        all_issues: list[Issue] = []
        for issue in issues:
            if issue is not None:
                all_issues.append(issue)
        return cls(
            new_states=states,
            issues=all_issues,
            degraded_passes=degraded_passes or [],
            fallback_events=fallback_events or [],
        )

    @staticmethod
    def terminate() -> OpcodeResult:
        """Return a terminal result with no successors or issues.

        Returns:
            An OpcodeResult flagged as terminal.

        """
        return OpcodeResult(new_states=[], issues=[], terminal=True)

    @classmethod
    def with_issue(
        cls,
        state: VMState,
        issue: Issue,
        degraded_passes: list[str] | None = None,
        fallback_events: list[FallbackEvent] | None = None,
    ) -> OpcodeResult:
        """Return one successor together with one emitted issue.

        Args:
            state: The successor VMState.
            issue: The issue detected during opcode dispatch.
            degraded_passes: Optional list of degradation reason strings if precision was lost.
            fallback_events: Optional structured fallback events for this opcode.

        Returns:
            An OpcodeResult holding the successor state and the issue.

        """
        return cls(
            new_states=[state],
            issues=[issue],
            degraded_passes=degraded_passes or [],
            fallback_events=fallback_events or [],
        )

    @classmethod
    def error(
        cls,
        issue: Issue,
        degraded_passes: list[str] | None = None,
        fallback_events: list[FallbackEvent] | None = None,
    ) -> OpcodeResult:
        """Return a terminal issue result without successor states.

        Args:
            issue: The terminating issue/error detected.
            degraded_passes: Optional list of degradation reason strings.
            fallback_events: Optional structured fallback events for this opcode.

        Returns:
            A terminal OpcodeResult with the issue.

        """
        return cls(
            new_states=[],
            issues=[issue],
            terminal=True,
            degraded_passes=degraded_passes or [],
            fallback_events=fallback_events or [],
        )
