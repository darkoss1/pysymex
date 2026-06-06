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

"""Fallback labels and events for protocol-aware builtins and iteration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

UNSUPPORTED_LENGTH_PROTOCOL: Final = "unsupported_length_protocol"
UNSUPPORTED_CONVERSION_PROTOCOL: Final = "unsupported_conversion_protocol"
UNSUPPORTED_ITERATION_PROTOCOL: Final = "unsupported_iteration_protocol"

PROTOCOL_BUILTIN_UNAVAILABLE_REASON: Final = "modeled protocol builtin could not be entered"
ITERATION_PROTOCOL_UNAVAILABLE_REASON: Final = "modeled iteration protocol could not be entered"


def unsupported_length_event(
    *,
    state: VMState,
    reason: str = PROTOCOL_BUILTIN_UNAVAILABLE_REASON,
) -> FallbackEvent:
    """Build a fallback event for unsupported length protocol builtin semantics."""
    return _unsupported_protocol_event(
        state=state,
        label=UNSUPPORTED_LENGTH_PROTOCOL,
        owner="execution.opcodes.protocol_builtins",
        reason=reason,
    )


def unsupported_conversion_event(
    *,
    state: VMState,
    reason: str = PROTOCOL_BUILTIN_UNAVAILABLE_REASON,
) -> FallbackEvent:
    """Build a fallback event for unsupported conversion protocol builtin semantics."""
    return _unsupported_protocol_event(
        state=state,
        label=UNSUPPORTED_CONVERSION_PROTOCOL,
        owner="execution.opcodes.protocol_builtins",
        reason=reason,
    )


def unsupported_iteration_event(
    *,
    state: VMState,
    reason: str = ITERATION_PROTOCOL_UNAVAILABLE_REASON,
    owner: str = "execution.opcodes.iteration",
) -> FallbackEvent:
    """Build a fallback event for unsupported iteration protocol semantics."""
    return _unsupported_protocol_event(
        state=state,
        label=UNSUPPORTED_ITERATION_PROTOCOL,
        owner=owner,
        reason=reason,
    )


def protocol_builtin_fallback_events(
    *,
    state: VMState,
    degraded_pass: str,
) -> list[FallbackEvent]:
    """Build fallback events for known protocol-builtin degraded labels."""
    if degraded_pass == UNSUPPORTED_LENGTH_PROTOCOL:
        return [unsupported_length_event(state=state)]
    if degraded_pass == UNSUPPORTED_CONVERSION_PROTOCOL:
        return [unsupported_conversion_event(state=state)]
    if degraded_pass == UNSUPPORTED_ITERATION_PROTOCOL:
        return [
            unsupported_iteration_event(
                state=state,
                reason=PROTOCOL_BUILTIN_UNAVAILABLE_REASON,
                owner="execution.opcodes.protocol_builtins",
            )
        ]
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
    "ITERATION_PROTOCOL_UNAVAILABLE_REASON",
    "PROTOCOL_BUILTIN_UNAVAILABLE_REASON",
    "UNSUPPORTED_CONVERSION_PROTOCOL",
    "UNSUPPORTED_ITERATION_PROTOCOL",
    "UNSUPPORTED_LENGTH_PROTOCOL",
    "protocol_builtin_fallback_events",
    "unsupported_conversion_event",
    "unsupported_iteration_event",
    "unsupported_length_event",
]
