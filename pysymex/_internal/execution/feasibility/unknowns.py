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

"""Shared handling for inconclusive feasibility checks at execution sites.

Opcode and model handlers frequently need to fork on a condition after asking
Z3 whether the branch is feasible.  SAT and UNSAT are definitive for the
encoded path.  UNKNOWN is not proof either way, so callers should preserve the
maybe-feasible path and attach an explicit diagnostic rather than silently
collapsing UNKNOWN into a boolean.

This module centralizes that policy so individual opcode handlers do not each
reimplement fallback-event wiring, degraded-pass deduplication, or terminal
result preservation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)

if TYPE_CHECKING:
    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@dataclass(frozen=True, slots=True)
class FeasibilityBranch:
    """Named branch outcome used to build UNKNOWN diagnostics."""

    name: str
    result: SolverResult


@dataclass(frozen=True, slots=True)
class UnknownFeasibilitySpec:
    """Stable metadata for one family of feasibility checks."""

    label: str
    owner: str
    subject: str
    false_positive_risk: RiskLevel = RiskLevel.MEDIUM
    false_negative_risk: RiskLevel = RiskLevel.MEDIUM


def may_be_feasible(result: SolverResult) -> bool:
    """Return whether a solver result should remain executable."""
    return not result.is_unsat


def unknown_branch_names(branches: list[FeasibilityBranch]) -> list[str]:
    """Return branch names with solver-UNKNOWN results, preserving first-seen order."""
    names: list[str] = []
    for branch in branches:
        if branch.result.is_unknown and branch.name not in names:
            names.append(branch.name)
    return names


def unknown_feasibility_events(
    *,
    state: VMState,
    spec: UnknownFeasibilitySpec,
    branches: list[FeasibilityBranch],
) -> list[FallbackEvent]:
    """Return one structured fallback event when any named branch is UNKNOWN."""
    names = unknown_branch_names(branches)
    if not names:
        return []
    return [
        FallbackEvent(
            kind=FallbackKind.UNKNOWN,
            label=spec.label,
            owner=spec.owner,
            reason=(f"solver could not establish {'/'.join(names)} {spec.subject} feasibility"),
            pc=state.pc,
            soundness=SoundnessTag.INCONCLUSIVE,
            false_positive_risk=spec.false_positive_risk,
            false_negative_risk=spec.false_negative_risk,
        ),
    ]


def degraded_passes_from_events(events: list[FallbackEvent]) -> list[str]:
    """Return stable, deduplicated degraded-pass labels for fallback events."""
    return list(dict.fromkeys(event.label for event in events))


def merge_degraded_passes(
    base: list[str],
    events: list[FallbackEvent],
) -> list[str]:
    """Return stable degraded-pass labels from existing labels plus events."""
    return list(dict.fromkeys([*base, *(event.label for event in events)]))


def append_fallback_events(result: OpcodeResult, events: list[FallbackEvent]) -> OpcodeResult:
    """Return *result* with fallback events/degraded labels appended."""
    if not events:
        return result

    from pysymex._internal.execution.dispatch.result import OpcodeResult

    return OpcodeResult(
        new_states=result.new_states,
        issues=result.issues,
        degraded_passes=merge_degraded_passes(result.degraded_passes, events),
        terminal=result.terminal,
        fallback_events=[*result.fallback_events, *events],
    )


def terminal_result_with_events(events: list[FallbackEvent]) -> OpcodeResult:
    """Return a terminal ``OpcodeResult`` while preserving fallback diagnostics."""
    from pysymex._internal.execution.dispatch.result import OpcodeResult

    if not events:
        return OpcodeResult.terminate()
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=degraded_passes_from_events(events),
        terminal=True,
        fallback_events=events,
    )
