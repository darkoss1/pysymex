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

"""Typed fallback and degraded-execution event data."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FallbackKind(StrEnum):
    """Broad family of fallback or degraded execution behavior."""

    PRECISION_LOSS = "precision_loss"
    RESOURCE_LIMIT = "resource_limit"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class RiskLevel(StrEnum):
    """Qualitative risk tag attached to a fallback event."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class SoundnessTag(StrEnum):
    """How a fallback affects verification claims."""

    INCONCLUSIVE = "inconclusive"
    PRECISION_LOSS = "precision_loss"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class FallbackEvent:
    """Structured internal record for one degraded or fallback behavior."""

    kind: FallbackKind
    label: str
    owner: str
    reason: str
    pc: int | None = None
    line_number: int | None = None
    function_name: str | None = None
    soundness: SoundnessTag = SoundnessTag.PRECISION_LOSS
    false_positive_risk: RiskLevel = RiskLevel.UNKNOWN
    false_negative_risk: RiskLevel = RiskLevel.UNKNOWN
