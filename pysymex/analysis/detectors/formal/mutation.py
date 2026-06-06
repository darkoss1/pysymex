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

"""Mutation robustness checks for detector formal logic."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex.analysis.detectors.formal.types import MutationResult
from pysymex.core.solver.engine.queries import check_sat_result
from pysymex.core.solver.engine.results import SolverResult


def run_mutation_analysis() -> list[MutationResult]:
    """Evaluate if proof obligations kill common logic mutants."""
    return [
        _division_by_zero_mutation(),
        _index_error_mutation(),
        _none_dereference_mutation(),
        _key_error_mutation(),
    ]


def _division_by_zero_mutation() -> MutationResult:
    """Perform mutation testing on division-by-zero detector formal model.

    Generates mutants representing logical variations of the division by zero risk
    expression and checks if the formal specification can distinguish (kill) them.

    Returns:
        A MutationResult summarizing the mutation score for division-by-zero.
    """
    d_is_int = z3.Bool("md_is_int")
    d_is_float = z3.Bool("md_is_float")
    d_int_zero = z3.Bool("md_int_zero")
    d_float_zero = z3.Bool("md_float_zero")
    risk = z3.Or(z3.And(d_is_int, d_int_zero), z3.And(d_is_float, d_float_zero))
    mutants = [
        z3.And(z3.And(d_is_int, d_int_zero), z3.And(d_is_float, d_float_zero)),
        z3.Or(z3.And(d_is_int, z3.Not(d_int_zero)), z3.And(d_is_float, d_float_zero)),
        z3.And(d_is_int, d_int_zero),
    ]
    return _mutation_result("division-by-zero", risk, mutants)


def _index_error_mutation() -> MutationResult:
    """Perform mutation testing on index bounds detector formal model.

    Generates mutants representing logical variations of the index error risk
    expression and checks if the formal specification can distinguish (kill) them.

    Returns:
        A MutationResult summarizing the mutation score for index-error.
    """
    is_list = z3.Bool("mi_is_list")
    is_int = z3.Bool("mi_is_int")
    ge_len = z3.Bool("mi_ge_len")
    lt_neg_len = z3.Bool("mi_lt_neg_len")
    risk = z3.And(is_list, is_int, z3.Or(ge_len, lt_neg_len))
    mutants = [
        z3.And(is_list, is_int, z3.And(ge_len, lt_neg_len)),
        z3.And(is_list, z3.Or(ge_len, lt_neg_len)),
        z3.And(is_list, is_int, z3.Not(z3.Or(ge_len, lt_neg_len))),
    ]
    return _mutation_result("index-error", risk, mutants)


def _none_dereference_mutation() -> MutationResult:
    """Perform mutation testing on None dereference detector formal model.

    Generates mutants representing logical variations of the None dereference risk
    expression and checks if the formal specification can distinguish (kill) them.

    Returns:
        A MutationResult summarizing the mutation score for none-dereference.
    """
    none = z3.Bool("mn_none")
    skipped = z3.Bool("mn_skipped")
    risk = z3.And(none, z3.Not(skipped))
    mutants = [
        z3.And(none, skipped),
        none,
        z3.Not(z3.And(none, z3.Not(skipped))),
    ]
    return _mutation_result("none-dereference", risk, mutants)


def _key_error_mutation() -> MutationResult:
    """Perform mutation testing on KeyError detector formal model.

    Generates mutants representing logical variations of the KeyError risk
    expression and checks if the formal specification can distinguish (kill) them.

    Returns:
        A MutationResult summarizing the mutation score for key-error.
    """
    is_dict = z3.Bool("mk_is_dict")
    contains_key = z3.Bool("mk_contains_key")
    risk = z3.And(is_dict, z3.Not(contains_key))
    mutants = [
        z3.And(is_dict, contains_key),
        is_dict,
        z3.Not(z3.And(is_dict, z3.Not(contains_key))),
    ]
    return _mutation_result("key-error", risk, mutants)


def _mutation_result(name: str, risk: z3.BoolRef, mutants: list[z3.BoolRef]) -> MutationResult:
    """Determine the mutation score by checking equivalence of mutants to a baseline risk.

    A mutant is considered killed if there exists a valuation of variables where the mutant
    and the baseline risk differ (i.e. `risk != mutant` is satisfiable).

    Args:
        name: Name of the detector being checked.
        risk: The baseline Z3 boolean expression for detector risk.
        mutants: A list of mutant Z3 boolean expressions to test.

    Returns:
        A MutationResult summarizing mutation counts and score.
    """
    killed = 0
    inconclusive = 0
    for mutant in mutants:
        risk_only = _sat_status([risk, z3.Not(mutant)])
        mutant_only = _sat_status([mutant, z3.Not(risk)])
        if risk_only.is_sat or mutant_only.is_sat:
            killed += 1
            continue
        if risk_only.is_unknown or mutant_only.is_unknown:
            inconclusive += 1
    return MutationResult(name, len(mutants), killed, killed / len(mutants), inconclusive)


def _sat_status(constraints: Iterable[z3.BoolRef]) -> SolverResult:
    """Return the structured solver status for a mutation distinction query."""
    return check_sat_result(constraints)


__all__ = ["run_mutation_analysis"]
