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

"""Formal verification harness for runtime detector logic.

Contains four layers of validation:

1. **SMT proof obligations** - via :func:`prove_smt_obligations` (imported from
   ``formal.specs``).
2. **Statistical property validation** - :func:`run_property_validation` runs
   randomised cases and measures false-positive / false-negative rates against
   Wilson upper-bound targets.
3. **Oracle differential validation** - :func:`run_oracle_differential_validation`
   compares detector decisions to independent concrete Python oracles.
4. **Mutation analysis** - via :func:`run_mutation_analysis` (imported from
   ``formal.mutation``).

Call :func:`build_machine_checkable_report` to collect all four layers into a
single JSON-serialisable report dict.
"""

from __future__ import annotations

from dataclasses import asdict

from pysymex.analysis.detectors.formal.mutation import run_mutation_analysis
from pysymex.analysis.detectors.formal.oracle_validation import (
    run_oracle_differential_validation,
)
from pysymex.analysis.detectors.formal.property_validation import run_property_validation
from pysymex.analysis.detectors.formal.specs import prove_smt_obligations, specs


def build_machine_checkable_report(samples: int = 400, seed: int = 7) -> dict[str, object]:
    """Build a comprehensive validation report including SMT proofs and stats.

    Args:
        samples: The number of randomized samples to generate for statistical checks.
        seed: Random seed for reproducibility.

    Returns:
        A dictionary containing specification data, proof results, statistical rates,
        mutation scores, and differential testing comparisons.
    """
    obligations = prove_smt_obligations()
    stats = run_property_validation(samples=samples, seed=seed)
    mutations = run_mutation_analysis()
    oracle_stats = run_oracle_differential_validation(
        samples=max(100, samples // 2), seed=seed + 13
    )

    return {
        "specs": [asdict(s) for s in specs()],
        "proof_obligations": [asdict(r) for r in obligations],
        "property_validation": [asdict(r) for r in stats],
        "mutation_analysis": [asdict(r) for r in mutations],
        "oracle_differential_validation": [asdict(r) for r in oracle_stats],
        "summary": {
            "all_obligations_passed": all(r.passed for r in obligations),
            "detectors_within_fp_target": [
                st.detector
                for st in stats
                if st.fp_upper_95
                <= next(sp.false_positive_target for sp in specs() if sp.detector == st.detector)
                and st.inconclusive_samples == 0
            ],
            "average_mutation_score": sum(m.mutation_score for m in mutations) / len(mutations),
            "mutation_analysis_inconclusive_mutants": sum(
                m.inconclusive_mutants for m in mutations
            ),
            "property_validation_inconclusive_samples": sum(
                st.inconclusive_samples for st in stats
            ),
            "oracle_mismatch_free": [
                r.detector
                for r in oracle_stats
                if r.mismatches == 0 and r.inconclusive_samples == 0
            ],
            "oracle_differential_inconclusive_samples": sum(
                r.inconclusive_samples for r in oracle_stats
            ),
            "samples": samples,
            "seed": seed,
        },
    }


__all__ = [
    "build_machine_checkable_report",
    "prove_smt_obligations",
    "run_mutation_analysis",
    "run_oracle_differential_validation",
    "run_property_validation",
    "specs",
]
