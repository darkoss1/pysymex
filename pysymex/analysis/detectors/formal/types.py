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

"""Formal detector result and specification types."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectorFormalSpec:
    """Formal specification metadata and performance targets for a detector."""

    detector: str
    risk_formula: str
    soundness_claim: str
    false_positive_target: float


@dataclass(frozen=True, slots=True)
class ProofObligationResult:
    """Result of an SMT proof obligation check."""

    detector: str
    obligation: str
    passed: bool
    status: str


@dataclass(frozen=True, slots=True)
class StatisticalResult:
    """Statistical rates of false positives and negatives from randomized checks."""

    detector: str
    samples: int
    false_positives: int
    false_negatives: int
    fp_rate: float
    fn_rate: float
    fp_upper_95: float
    fn_upper_95: float
    inconclusive_samples: int = 0


@dataclass(frozen=True, slots=True)
class MutationResult:
    """Mutation testing counts and score for a detector spec."""

    detector: str
    total_mutants: int
    killed_mutants: int
    mutation_score: float
    inconclusive_mutants: int = 0


@dataclass(frozen=True, slots=True)
class OracleResult:
    """Differential validation result comparing detector to concrete execution."""

    detector: str
    samples: int
    mismatches: int
    mismatch_rate: float
    mismatch_upper_95: float
    inconclusive_samples: int = 0


__all__ = [
    "DetectorFormalSpec",
    "MutationResult",
    "OracleResult",
    "ProofObligationResult",
    "StatisticalResult",
]
