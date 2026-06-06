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

"""Confidence scoring for type inference results based on evidence strength."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ConfidenceScore:
    """
    Confidence score for type inference.
    Factors:
    - Source reliability (annotation > inference > unknown)
    - Path length (shorter paths = higher confidence)
    - Corroboration (multiple sources agreeing)
    - Narrowing (type guards increase confidence)
    """

    score: float
    source: str
    factors: dict[str, float] = field(default_factory=dict[str, float])

    @classmethod
    def from_annotation(cls) -> ConfidenceScore:
        """High confidence from explicit annotation."""
        return cls(
            score=0.95,
            source="annotation",
            factors={"explicit": 0.95},
        )

    @classmethod
    def from_literal(cls) -> ConfidenceScore:
        """Very high confidence from literal value."""
        return cls(
            score=0.99,
            source="literal",
            factors={"literal": 0.99},
        )

    @classmethod
    def from_inference(cls, reliability: float = 0.7) -> ConfidenceScore:
        """Medium confidence from inference."""
        return cls(
            score=reliability,
            source="inferred",
            factors={"inference": reliability},
        )

    @classmethod
    def from_isinstance_guard(cls) -> ConfidenceScore:
        """High confidence from isinstance check."""
        return cls(
            score=0.9,
            source="isinstance_guard",
            factors={"type_guard": 0.9},
        )

    @classmethod
    def from_none_check(cls) -> ConfidenceScore:
        """High confidence from None check."""
        return cls(
            score=0.9,
            source="none_check",
            factors={"none_guard": 0.9},
        )

    @classmethod
    def unknown(cls) -> ConfidenceScore:
        """Low confidence for unknown."""
        return cls(
            score=0.3,
            source="unknown",
            factors={"unknown": 0.3},
        )

    def combine(self, other: ConfidenceScore) -> ConfidenceScore:
        """Combine confidence scores."""
        combined_score = min(self.score, other.score)
        combined_factors = {**self.factors, **other.factors}
        return ConfidenceScore(
            score=combined_score,
            source=f"{self.source}+{other.source}",
            factors=combined_factors,
        )

    def boost_from_guard(self, boost: float = 0.1) -> ConfidenceScore:
        """Boost confidence from a type guard."""
        new_score = min(1.0, self.score + boost)
        return ConfidenceScore(
            score=new_score,
            source=self.source,
            factors={**self.factors, "guard_boost": boost},
        )
