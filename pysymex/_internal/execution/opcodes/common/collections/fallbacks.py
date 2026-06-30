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

from typing import TYPE_CHECKING, Final

from pysymex._internal.core.classes.mapping_protocol.extraction import (
    UNSUPPORTED_MAPPING_PROTOCOL,
)
from pysymex._internal.core.types.containers.slices import (
    UNSUPPORTED_SLICE_ABSTRACTION,
)
from pysymex._internal.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)
from pysymex._internal.execution.opcodes.common.lowering.types import (
    UNSUPPORTED_SUBSCRIPT_ABSTRACTION,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


class CollectionFallbackEvents:
    """Domain owner for collection opcode fallback event construction."""

    UNSUPPORTED_HASHED_COLLECTION_PROTOCOL: Final = "unsupported_hashed_collection_protocol"
    UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL: Final = "unsupported_collection_mutation_protocol"

    @staticmethod
    def unsupported_subscript(*, state: VMState, reason: str) -> FallbackEvent:
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

    @staticmethod
    def unsupported_slice(*, state: VMState, reason: str) -> FallbackEvent:
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

    @staticmethod
    def unsupported_mapping(*, state: VMState, reason: str) -> FallbackEvent:
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

    @staticmethod
    def unsupported_hashed_collection(*, state: VMState, reason: str) -> FallbackEvent:
        """Build the fallback event for unsupported modeled object hashing in collections."""
        return FallbackEvent(
            kind=FallbackKind.UNSUPPORTED,
            label=CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL,
            owner="execution.opcodes.collections",
            reason=reason,
            pc=state.pc,
            soundness=SoundnessTag.UNSUPPORTED,
            false_positive_risk=RiskLevel.MEDIUM,
            false_negative_risk=RiskLevel.HIGH,
        )

    @staticmethod
    def unsupported_collection_mutation(*, state: VMState, reason: str) -> FallbackEvent:
        """Build the fallback event for unsupported collection mutation semantics."""
        return FallbackEvent(
            kind=FallbackKind.UNSUPPORTED,
            label=CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL,
            owner="execution.opcodes.collections",
            reason=reason,
            pc=state.pc,
            soundness=SoundnessTag.UNSUPPORTED,
            false_positive_risk=RiskLevel.MEDIUM,
            false_negative_risk=RiskLevel.HIGH,
        )

    @staticmethod
    def for_degraded_passes(
        *,
        state: VMState,
        degraded_passes: list[str],
        reason: str,
    ) -> list[FallbackEvent]:
        """Return collection fallback events for explicit, supported collection labels."""
        events: list[FallbackEvent] = []
        for degraded_pass in degraded_passes:
            if degraded_pass == UNSUPPORTED_SUBSCRIPT_ABSTRACTION:
                events.append(
                    CollectionFallbackEvents.unsupported_subscript(state=state, reason=reason),
                )
            elif degraded_pass == UNSUPPORTED_SLICE_ABSTRACTION:
                events.append(
                    CollectionFallbackEvents.unsupported_slice(state=state, reason=reason),
                )
            elif degraded_pass == UNSUPPORTED_MAPPING_PROTOCOL:
                events.append(
                    CollectionFallbackEvents.unsupported_mapping(state=state, reason=reason),
                )
            elif degraded_pass == CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL:
                events.append(
                    CollectionFallbackEvents.unsupported_hashed_collection(
                        state=state,
                        reason=reason,
                    ),
                )
            elif degraded_pass == CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL:
                events.append(
                    CollectionFallbackEvents.unsupported_collection_mutation(
                        state=state,
                        reason=reason,
                    ),
                )
        return events
