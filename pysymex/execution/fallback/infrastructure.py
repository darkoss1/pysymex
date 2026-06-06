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

"""Fallback labels and events for optional execution infrastructure failures."""

from __future__ import annotations

from typing import Final

from pysymex.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)

STATE_MERGER_DEGRADED_PASS: Final = "state_merger"
FP_FILTERING_DEGRADED_PASS: Final = "fp_filtering"
CROSS_FUNCTION_DEGRADED_PASS: Final = "cross_function"
TYPE_INFERENCE_DEGRADED_PASS: Final = "type_inference"


def state_merger_prepass_event() -> FallbackEvent:
    """Build the fallback event for failed state-merger join-point detection."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=STATE_MERGER_DEGRADED_PASS,
        owner="execution.scheduling.state_merger",
        reason="state merger join-point detection failed; continuing without join metadata",
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.LOW,
        false_negative_risk=RiskLevel.MEDIUM,
    )


def fp_filtering_event() -> FallbackEvent:
    """Build the fallback event for failed final false-positive filtering."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=FP_FILTERING_DEGRADED_PASS,
        owner="execution.detectors.fp_filtering",
        reason="false-positive filtering failed; raw issues were returned",
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.HIGH,
        false_negative_risk=RiskLevel.LOW,
    )


def cross_function_prepass_event() -> FallbackEvent:
    """Build the fallback event for failed cross-function analysis."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=CROSS_FUNCTION_DEGRADED_PASS,
        owner="analysis.cross_function",
        reason="cross-function analysis failed; continuing without interprocedural summaries",
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


def type_inference_prepass_event() -> FallbackEvent:
    """Build the fallback event for failed type-inference analysis."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=TYPE_INFERENCE_DEGRADED_PASS,
        owner="analysis.type_inference",
        reason="type inference pre-pass failed; continuing without inferred types",
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.MEDIUM,
    )
