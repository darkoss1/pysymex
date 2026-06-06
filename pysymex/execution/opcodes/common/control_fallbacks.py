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

"""Fallback labels and event builders for control-flow protocol abstractions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

LIST_TO_TUPLE_TYPE_UNCERTAIN = "list_to_tuple_type_uncertain"
LIST_TO_TUPLE_TYPE_UNCERTAIN_REASON = (
    "LIST_TO_TUPLE source type could not be proven list-compatible"
)
UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL = "unsupported_context_manager_protocol"
UNSUPPORTED_GENERATOR = "unsupported_generator"


def list_to_tuple_type_uncertain_event(*, state: VMState) -> FallbackEvent:
    """Build a fallback event for imprecise LIST_TO_TUPLE lowering."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=LIST_TO_TUPLE_TYPE_UNCERTAIN,
        owner="execution.opcodes.control",
        reason=LIST_TO_TUPLE_TYPE_UNCERTAIN_REASON,
        pc=state.pc,
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.MEDIUM,
    )


def unsupported_context_manager_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for unsupported context-manager protocol execution."""
    return FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label=UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL,
        owner="execution.opcodes.control",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.UNSUPPORTED,
        false_positive_risk=RiskLevel.HIGH,
        false_negative_risk=RiskLevel.HIGH,
    )


def unsupported_generator_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for unsupported generator/async generator semantics."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=UNSUPPORTED_GENERATOR,
        owner="execution.opcodes.control",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.LOW,
        false_negative_risk=RiskLevel.HIGH,
    )
