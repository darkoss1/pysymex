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

"""Fallback labels and event builders for modeled class construction."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

UNSUPPORTED_CONSTRUCTION_PROTOCOL = "unsupported_construction_protocol"

CONSTRUCTOR_ENTRY_UNAVAILABLE_REASON = "modeled class __new__ could not be entered"
CONSTRUCTOR_RETURN_UNCERTAIN_REASON = (
    "__new__ returned a possible object whose class relationship to the requested class is "
    "uncertain"
)
CONSTRUCTOR_INIT_UNAVAILABLE_REASON = (
    "modeled effective __init__ after __new__ could not be entered"
)
METACLASS_CALL_UNAVAILABLE_REASON = "modeled metaclass __call__ could not be entered"


def unsupported_construction_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for unsupported modeled construction semantics."""
    return FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label=UNSUPPORTED_CONSTRUCTION_PROTOCOL,
        owner="execution.calls.construction",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.UNSUPPORTED,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def construction_return_fallback_events(
    *, state: VMState, degraded_pass: str
) -> list[FallbackEvent]:
    """Return construction events for a degraded protocol return, if applicable."""
    if degraded_pass != UNSUPPORTED_CONSTRUCTION_PROTOCOL:
        return []
    return [
        unsupported_construction_event(
            state=state,
            reason=CONSTRUCTOR_RETURN_UNCERTAIN_REASON,
        )
    ]
