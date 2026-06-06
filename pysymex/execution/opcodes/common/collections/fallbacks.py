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

"""Fallback event builders for collection and slice opcode abstractions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag
from pysymex.core.types.containers.slices import (
    UNSUPPORTED_SLICE_ABSTRACTION,
)
from pysymex.execution.opcodes.common.lowering.types import UNSUPPORTED_SUBSCRIPT_ABSTRACTION
from pysymex.execution.opcodes.common.collections.mapping_protocol import (
    UNSUPPORTED_MAPPING_PROTOCOL,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

UNSUPPORTED_HASHED_COLLECTION_PROTOCOL = "unsupported_hashed_collection_protocol"


def unsupported_subscript_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build the fallback event for unsupported subscript precision loss."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=UNSUPPORTED_SUBSCRIPT_ABSTRACTION,
        owner="execution.opcodes.collections",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def unsupported_slice_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build the fallback event for unsupported slice precision loss."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=UNSUPPORTED_SLICE_ABSTRACTION,
        owner="execution.opcodes.collections",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def unsupported_mapping_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build the fallback event for inconclusive modeled mapping protocol extraction."""
    return FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label=UNSUPPORTED_MAPPING_PROTOCOL,
        owner="execution.opcodes.collections",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.UNSUPPORTED,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def unsupported_hashed_collection_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build the fallback event for unsupported modeled object hashing in collections."""
    return FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label=UNSUPPORTED_HASHED_COLLECTION_PROTOCOL,
        owner="execution.opcodes.collections",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.UNSUPPORTED,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def collection_fallback_events(
    *,
    state: VMState,
    degraded_passes: list[str],
    reason: str,
) -> list[FallbackEvent]:
    """Return collection fallback events for explicit, supported collection labels."""
    events: list[FallbackEvent] = []
    for degraded_pass in degraded_passes:
        if degraded_pass == UNSUPPORTED_SUBSCRIPT_ABSTRACTION:
            events.append(unsupported_subscript_event(state=state, reason=reason))
        elif degraded_pass == UNSUPPORTED_SLICE_ABSTRACTION:
            events.append(unsupported_slice_event(state=state, reason=reason))
        elif degraded_pass == UNSUPPORTED_MAPPING_PROTOCOL:
            events.append(unsupported_mapping_event(state=state, reason=reason))
        elif degraded_pass == UNSUPPORTED_HASHED_COLLECTION_PROTOCOL:
            events.append(unsupported_hashed_collection_event(state=state, reason=reason))
    return events
