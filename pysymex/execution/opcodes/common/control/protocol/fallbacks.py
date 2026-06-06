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

"""Fallback labels and events for modeled control/comparison protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.opcodes.common.numeric.fallbacks import (
    unsupported_numeric_reflection_event,
)
from pysymex.execution.opcodes.common.numeric.labels import UNSUPPORTED_NUMERIC_REFLECTION

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

UNSUPPORTED_TRUTH_PROTOCOL: Final = "unsupported_truth_protocol"
UNSUPPORTED_MEMBERSHIP_PROTOCOL: Final = "unsupported_membership_protocol"
UNSUPPORTED_COMPARISON_PROTOCOL: Final = "unsupported_comparison_protocol"
UNSUPPORTED_COMPARISON_REFLECTION: Final = "unsupported_comparison_reflection"
UNSUPPORTED_INIT_RETURN_PROTOCOL: Final = "unsupported_init_return_protocol"

TRUTH_CALL_UNAVAILABLE_REASON: Final = "modeled truth protocol could not be entered"
MEMBERSHIP_CALL_UNAVAILABLE_REASON: Final = "modeled membership protocol could not be entered"
COMPARISON_CALL_UNAVAILABLE_REASON: Final = "modeled comparison protocol could not be entered"
PROTOCOL_FALLBACK_UNAVAILABLE_REASON: Final = (
    "modeled protocol fallback candidate could not be entered"
)
COMPARISON_REFLECTION_UNCERTAIN_REASON: Final = (
    "rich comparison NotImplemented reflection could not be completed precisely"
)
INIT_RETURN_UNCERTAIN_REASON: Final = "__init__ return may violate the None-only contract"
LENGTH_RETURN_UNCERTAIN_REASON: Final = "modeled __len__ return could not be proven CPython-valid"


def unsupported_truth_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for unsupported truth protocol semantics."""
    return _unsupported_protocol_event(
        state=state,
        label=UNSUPPORTED_TRUTH_PROTOCOL,
        owner="execution.opcodes.control.truth",
        reason=reason,
    )


def unsupported_membership_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for unsupported membership protocol semantics."""
    return _unsupported_protocol_event(
        state=state,
        label=UNSUPPORTED_MEMBERSHIP_PROTOCOL,
        owner="execution.opcodes.compare.membership",
        reason=reason,
    )


def unsupported_comparison_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for unsupported rich-comparison semantics."""
    return _unsupported_protocol_event(
        state=state,
        label=UNSUPPORTED_COMPARISON_PROTOCOL,
        owner="execution.opcodes.compare",
        reason=reason,
    )


def unsupported_comparison_reflection_event(
    *,
    state: VMState,
    reason: str = COMPARISON_REFLECTION_UNCERTAIN_REASON,
) -> FallbackEvent:
    """Build a fallback event for incomplete equality reflection semantics."""
    return _unsupported_protocol_event(
        state=state,
        label=UNSUPPORTED_COMPARISON_REFLECTION,
        owner="execution.opcodes.compare.reflection",
        reason=reason,
    )


def unsupported_init_return_event(
    *,
    state: VMState,
    reason: str = INIT_RETURN_UNCERTAIN_REASON,
) -> FallbackEvent:
    """Build a fallback event for ambiguous modeled ``__init__`` returns."""
    return _unsupported_protocol_event(
        state=state,
        label=UNSUPPORTED_INIT_RETURN_PROTOCOL,
        owner="execution.opcodes.control.init_return",
        reason=reason,
    )


def protocol_return_fallback_events(
    *,
    state: VMState,
    degraded_pass: str,
) -> list[FallbackEvent]:
    """Build typed fallback events for known protocol-return degraded labels."""
    if degraded_pass == UNSUPPORTED_TRUTH_PROTOCOL:
        return [unsupported_truth_event(state=state, reason=LENGTH_RETURN_UNCERTAIN_REASON)]
    if degraded_pass == UNSUPPORTED_MEMBERSHIP_PROTOCOL:
        return [unsupported_membership_event(state=state, reason=LENGTH_RETURN_UNCERTAIN_REASON)]
    if degraded_pass == UNSUPPORTED_COMPARISON_REFLECTION:
        return [unsupported_comparison_reflection_event(state=state)]
    if degraded_pass == UNSUPPORTED_NUMERIC_REFLECTION:
        return [unsupported_numeric_reflection_event(state=state)]
    if degraded_pass == UNSUPPORTED_INIT_RETURN_PROTOCOL:
        return [unsupported_init_return_event(state=state)]
    return []


def _unsupported_protocol_event(
    *,
    state: VMState,
    label: str,
    owner: str,
    reason: str,
) -> FallbackEvent:
    """Build the common unsupported protocol event shape."""
    return FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label=label,
        owner=owner,
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.UNSUPPORTED,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


__all__ = [
    "COMPARISON_CALL_UNAVAILABLE_REASON",
    "COMPARISON_REFLECTION_UNCERTAIN_REASON",
    "INIT_RETURN_UNCERTAIN_REASON",
    "LENGTH_RETURN_UNCERTAIN_REASON",
    "MEMBERSHIP_CALL_UNAVAILABLE_REASON",
    "PROTOCOL_FALLBACK_UNAVAILABLE_REASON",
    "TRUTH_CALL_UNAVAILABLE_REASON",
    "UNSUPPORTED_COMPARISON_PROTOCOL",
    "UNSUPPORTED_COMPARISON_REFLECTION",
    "UNSUPPORTED_INIT_RETURN_PROTOCOL",
    "UNSUPPORTED_MEMBERSHIP_PROTOCOL",
    "UNSUPPORTED_TRUTH_PROTOCOL",
    "protocol_return_fallback_events",
    "unsupported_comparison_event",
    "unsupported_comparison_reflection_event",
    "unsupported_init_return_event",
    "unsupported_membership_event",
    "unsupported_truth_event",
]
