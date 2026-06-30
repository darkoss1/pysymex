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

"""Fallback naming and events for unresolved call targets."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pysymex._internal.execution.calls.havoc import UNMODELED_CALL_ABSTRACTION
from pysymex._internal.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


class CallFallbackEvents:
    """Domain owner for call-target fallback labels and event construction."""

    UNSUPPORTED_CALL_PROTOCOL: Final = "unsupported_call_protocol"
    CALL_TARGET_NONE_FEASIBILITY_UNKNOWN: Final = "call_target_none_feasibility_unknown"

    @staticmethod
    def target_name(func_obj: object) -> str:
        """Return the best stable call target name available for fallback events."""
        for attr_name in ("model_name", "__qualname__", "__name__", "_func_name", "name"):
            candidate = getattr(func_obj, attr_name, None)
            if isinstance(candidate, str) and candidate:
                return candidate
        return type(func_obj).__name__

    @staticmethod
    def unsupported_call_protocol(*, state: VMState) -> FallbackEvent:
        """Build the fallback event for unsupported symbolic ``__call__`` protocol paths."""
        return FallbackEvent(
            kind=FallbackKind.UNSUPPORTED,
            label=CallFallbackEvents.UNSUPPORTED_CALL_PROTOCOL,
            owner="execution.calls",
            reason="symbolic __call__ target could not be modeled or entered interprocedurally",
            pc=state.pc,
            soundness=SoundnessTag.UNSUPPORTED,
            false_positive_risk=RiskLevel.LOW,
            false_negative_risk=RiskLevel.HIGH,
        )

    @staticmethod
    def unmodeled_call_havoc(*, state: VMState, call_name: str) -> FallbackEvent:
        """Build the fallback event for unmodeled call havoc."""
        return FallbackEvent(
            kind=FallbackKind.PRECISION_LOSS,
            label=UNMODELED_CALL_ABSTRACTION,
            owner="execution.calls",
            reason=f"unmodeled call target {call_name!r} abstracted with havoc",
            pc=state.pc,
            soundness=SoundnessTag.PRECISION_LOSS,
            false_positive_risk=RiskLevel.MEDIUM,
            false_negative_risk=RiskLevel.HIGH,
        )
