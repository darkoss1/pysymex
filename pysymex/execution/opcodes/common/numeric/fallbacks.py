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

"""Fallback event builders for numeric opcode abstractions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.opcodes.common.numeric.labels import (
    NUMERIC_TYPE_ERROR_FEASIBILITY_UNKNOWN,
    SYMBOLIC_POWER_ABSTRACTION,
    SYMBOLIC_SHIFT_ABSTRACTION,
    UNARY_POSITIVE_TYPE_UNCERTAIN,
    UNSUPPORTED_NUMERIC_ABSTRACTION,
    UNSUPPORTED_NUMERIC_REFLECTION,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

NUMERIC_REFLECTION_UNCERTAIN_REASON = (
    "numeric NotImplemented reflection could not be completed precisely"
)


def unsupported_numeric_event(
    *,
    state: VMState,
    reason: str,
    unsupported_protocol: bool = False,
) -> FallbackEvent:
    """Build a fallback event for unsupported numeric semantics."""
    soundness = SoundnessTag.UNSUPPORTED if unsupported_protocol else SoundnessTag.PRECISION_LOSS
    kind = FallbackKind.UNSUPPORTED if unsupported_protocol else FallbackKind.PRECISION_LOSS
    return FallbackEvent(
        kind=kind,
        label=UNSUPPORTED_NUMERIC_ABSTRACTION,
        owner="execution.opcodes.numeric",
        reason=reason,
        pc=state.pc,
        soundness=soundness,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def symbolic_power_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for symbolic power abstraction."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=SYMBOLIC_POWER_ABSTRACTION,
        owner="execution.opcodes.numeric",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def symbolic_shift_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for symbolic shift abstraction."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=SYMBOLIC_SHIFT_ABSTRACTION,
        owner="execution.opcodes.numeric",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def unary_positive_uncertain_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for ambiguous unary-positive symbolic affinity."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=UNARY_POSITIVE_TYPE_UNCERTAIN,
        owner="execution.opcodes.numeric",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.LOW,
        false_negative_risk=RiskLevel.MEDIUM,
    )


def unsupported_numeric_reflection_event(
    *,
    state: VMState,
    reason: str = NUMERIC_REFLECTION_UNCERTAIN_REASON,
) -> FallbackEvent:
    """Build a fallback event for incomplete numeric reflection semantics."""
    return FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label=UNSUPPORTED_NUMERIC_REFLECTION,
        owner="execution.opcodes.numeric.reflection",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.UNSUPPORTED,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def type_error_feasibility_unknown_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for an inconclusive numeric TypeError report query."""
    return FallbackEvent(
        kind=FallbackKind.UNKNOWN,
        label=NUMERIC_TYPE_ERROR_FEASIBILITY_UNKNOWN,
        owner="execution.opcodes.numeric",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.INCONCLUSIVE,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.MEDIUM,
    )
