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

"""Effect-obligation status classification and diagnostics."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.contracts.effects.locations import event_allowed_by_assigns
from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import SolverStatus, UnsupportedReason

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from pysymex._internal.core.effects.events import WriteEvent
    from pysymex._internal.core.state.record import VMState


class AssignsEffectPolicy:
    """Policy owner for ``@assigns`` frame-condition classification."""

    @staticmethod
    def classify(
        state: VMState,
        func: Callable[..., object],
        allowed_locations: frozenset[str],
        events: Sequence[WriteEvent],
    ) -> tuple[VerificationResult, str, tuple[UnsupportedReason, ...]]:
        """Return the evidence classification for one ``@assigns`` declaration."""
        if not events:
            return VerificationResult.VERIFIED, "Frame condition observed no modeled writes", ()
        if not allowed_locations:
            return (
                VerificationResult.VIOLATED,
                writes_message("Frame condition forbids all modeled writes", events),
                (UnsupportedReason.EFFECT_WRITE,),
            )
        violating_precise = [
            event
            for event in events
            if event.precise
            and not event_allowed_by_assigns(
                state,
                func,
                event,
                allowed_locations,
            )
        ]
        if violating_precise:
            return (
                VerificationResult.VIOLATED,
                writes_message(
                    "Frame condition wrote outside declared locations",
                    violating_precise,
                ),
                (UnsupportedReason.EFFECT_WRITE,),
            )
        imprecise = [event for event in events if not event.precise]
        if imprecise:
            return (
                VerificationResult.UNKNOWN,
                writes_message("Frame condition depends on imprecise alias ownership", imprecise),
                (UnsupportedReason.ALIAS_IMPRECISION,),
            )
        return VerificationResult.VERIFIED, "Frame condition allowed all modeled writes", ()


def effect_solver_status(status: VerificationResult) -> SolverStatus:
    """Map non-solver effect classifications into evidence solver status."""
    if status is VerificationResult.UNKNOWN:
        return SolverStatus.UNKNOWN
    return SolverStatus.NOT_RUN


def assigns_condition(locations: frozenset[str]) -> str:
    """Return the display condition for an assigns declaration."""
    if not locations:
        return "assigns()"
    return "assigns(" + ", ".join(sorted(locations)) + ")"


def writes_message(prefix: str, events: Sequence[WriteEvent]) -> str:
    """Return a compact write-event diagnostic message."""
    locations = ", ".join(f"{event.location} via {event.source}" for event in events[:4])
    if len(events) > 4:
        locations = f"{locations}, +{len(events) - 4} more"
    return f"{prefix}: {locations}"
