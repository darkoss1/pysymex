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

"""Fallback labels and events for modeled attribute and descriptor protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState

UNSUPPORTED_ATTRIBUTE_PROTOCOL: Final = "unsupported_attribute_protocol"
UNSUPPORTED_DESCRIPTOR_PROTOCOL: Final = "unsupported_descriptor_protocol"
UNMODELED_ATTRIBUTE_HAVOC: Final = "unmodeled_attribute_havoc"


def unsupported_attribute_protocol(state: VMState, *, reason: str) -> OpcodeResult:
    """Return a terminal unsupported-attribute result with structured fallback data."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_ATTRIBUTE_PROTOCOL],
        fallback_events=[flag_unsupported_attribute_protocol(state=state, reason=reason)],
        terminal=True,
    )


def unsupported_descriptor_protocol(state: VMState, *, reason: str) -> OpcodeResult:
    """Return a terminal unsupported-descriptor result with structured fallback data."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_DESCRIPTOR_PROTOCOL],
        fallback_events=[flag_unsupported_descriptor_protocol(state=state, reason=reason)],
        terminal=True,
    )


def flag_unsupported_attribute_protocol(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for unsupported dynamic attribute protocol semantics."""
    return _flag_unsupported_attribute_family(
        state=state,
        label=UNSUPPORTED_ATTRIBUTE_PROTOCOL,
        reason=reason,
    )


def flag_unsupported_descriptor_protocol(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for unsupported descriptor protocol semantics."""
    return _flag_unsupported_attribute_family(
        state=state,
        label=UNSUPPORTED_DESCRIPTOR_PROTOCOL,
        reason=reason,
    )


def unmodeled_attribute_havoc_event(
    *,
    state: VMState,
    object_name: str,
    attr_name: str,
) -> FallbackEvent:
    """Build a precision-loss event for attribute reads from havoc values."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=UNMODELED_ATTRIBUTE_HAVOC,
        owner="execution.opcodes.attribute",
        reason=f"havoc attribute {attr_name!r} read from {object_name!r} produced an unconstrained value",
        pc=state.pc,
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def _flag_unsupported_attribute_family(
    *,
    state: VMState,
    label: str,
    reason: str,
) -> FallbackEvent:
    """Build the common unsupported attribute/descriptor event shape."""
    return FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label=label,
        owner="execution.opcodes.attribute",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.UNSUPPORTED,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )
