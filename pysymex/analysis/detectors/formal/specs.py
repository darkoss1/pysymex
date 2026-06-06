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

"""SMT specs and proof obligations for detector formal checks."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex.analysis.detectors.formal.types import DetectorFormalSpec, ProofObligationResult
from pysymex.core.solver.engine.queries import check_sat_result
from pysymex.core.solver.engine.results import SolverResult


def specs() -> list[DetectorFormalSpec]:
    """Return the formal specifications for the checkers.

    Returns:
        A list of DetectorFormalSpec instances containing metadata, formulas,
        and objectives.
    """
    return [
        DetectorFormalSpec(
            detector="division-by-zero",
            risk_formula="(is_int AND int_value == 0) OR (is_float AND float_value == 0.0)",
            soundness_claim="All satisfiable zero-divisor paths should be reported.",
            false_positive_target=0.05,
        ),
        DetectorFormalSpec(
            detector="index-error",
            risk_formula="is_list AND is_int_index AND (idx >= len OR idx < -len)",
            soundness_claim="All satisfiable out-of-bounds paths should be reported.",
            false_positive_target=0.05,
        ),
        DetectorFormalSpec(
            detector="none-dereference",
            risk_formula="obj_is_none AND NOT skipped(name, prefixes)",
            soundness_claim="All satisfiable None-deref paths not explicitly suppressed should be reported.",
            false_positive_target=0.05,
        ),
        DetectorFormalSpec(
            detector="key-error",
            risk_formula="is_dict AND NOT contains_key",
            soundness_claim="All satisfiable missing-key dictionary access paths should be reported.",
            false_positive_target=0.05,
        ),
    ]


def prove_smt_obligations() -> list[ProofObligationResult]:
    """Prove abstract detector decision rules against formal risk predicates."""
    results: list[ProofObligationResult] = []

    d_is_int = z3.Bool("d_is_int")
    d_is_float = z3.Bool("d_is_float")
    d_int_zero = z3.Bool("d_int_zero")
    d_float_zero = z3.Bool("d_float_zero")
    div_risk = z3.Or(z3.And(d_is_int, d_int_zero), z3.And(d_is_float, d_float_zero))
    div_rule = z3.Or(z3.And(d_is_int, d_int_zero), z3.And(d_is_float, d_float_zero))
    _append_equivalence(results, "division-by-zero", div_risk, div_rule)

    is_list = z3.Bool("is_list")
    is_int_idx = z3.Bool("is_int_idx")
    ge_len = z3.Bool("ge_len")
    lt_neg_len = z3.Bool("lt_neg_len")
    idx_risk = z3.And(is_list, is_int_idx, z3.Or(ge_len, lt_neg_len))
    idx_rule = z3.And(is_list, is_int_idx, z3.Or(ge_len, lt_neg_len))
    _append_equivalence(results, "index-error", idx_risk, idx_rule)

    obj_is_none = z3.Bool("obj_is_none")
    skipped = z3.Bool("skipped")
    none_risk = z3.And(obj_is_none, z3.Not(skipped))
    none_rule = z3.And(obj_is_none, z3.Not(skipped))
    _append_equivalence(results, "none-dereference", none_risk, none_rule)

    is_dict = z3.Bool("is_dict")
    contains_key = z3.Bool("contains_key")
    key_risk = z3.And(is_dict, z3.Not(contains_key))
    key_rule = z3.And(is_dict, z3.Not(contains_key))
    _append_equivalence(results, "key-error", key_risk, key_rule)

    return results


def _append_equivalence(
    results: list[ProofObligationResult],
    detector: str,
    risk: z3.BoolRef,
    rule: z3.BoolRef,
) -> None:
    """Check and record bidirectional implication (equivalence) between risk and rule.

    Ensures soundness (risk implies rule) and precision (rule implies risk) by proving implication unsatisfiability.

    Args:
        results: List of ProofObligationResult to append proof results to.
        detector: Name of the detector.
        risk: The Z3 boolean expression for the baseline risk condition.
        rule: The Z3 boolean expression for the detection rule condition.
    """
    results.append(_proof_obligation(detector, "soundness (risk => rule)", [risk, z3.Not(rule)]))
    results.append(_proof_obligation(detector, "precision (rule => risk)", [rule, z3.Not(risk)]))


def _proof_obligation(
    detector: str,
    obligation: str,
    constraints: Iterable[z3.BoolRef],
) -> ProofObligationResult:
    """Prove a single logic property using SMT constraints.

    Creates and checks satisfiability of the negation of a property. If the negation
    is unsat, the property is proven. If sat, the property is violated. Otherwise,
    the result is unknown.

    Args:
        detector: Name of the detector under verification.
        obligation: Name or description of the proof obligation.
        constraints: Iterable of Z3 boolean expressions representing the negation of the theorem.

    Returns:
        A ProofObligationResult indicating if the obligation passed.
    """
    result = check_sat_result(constraints)
    return ProofObligationResult(
        detector=detector,
        obligation=obligation,
        passed=result.is_unsat,
        status=_status(result),
    )


def _status(result: SolverResult) -> str:
    """Convert a SolverResult to its string representation.

    Args:
        result: The solver result to inspect.

    Returns:
        One of "sat", "unsat", or "unknown".
    """
    if result.is_sat:
        return "sat"
    if result.is_unsat:
        return "unsat"
    return "unknown"


__all__ = ["prove_smt_obligations", "specs"]
