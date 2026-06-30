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

"""String and string/integer witness probes for detector feasibility evidence."""

from __future__ import annotations

import itertools
from typing import TYPE_CHECKING

import z3

import pysymex._internal.analysis.evidence.cache as _evidence_cache
import pysymex._internal.analysis.evidence.solvers as _evidence_solvers
import pysymex._internal.analysis.evidence.string.substitutions as _string_substitutions
import pysymex._internal.analysis.evidence.witness.models as _witness_models
from pysymex._internal.analysis.evidence.errors import EVIDENCE_SOLVER_FAILURES
from pysymex._internal.analysis.evidence.integer.candidates import IntegerWitnesses
from pysymex._internal.analysis.evidence.integer.equalities import IntegerEqualities
from pysymex._internal.analysis.evidence.string.context import (
    has_string_context_integers,
    string_context_integer_assignment,
)
from pysymex._internal.analysis.evidence.string.value.sets import (
    bin_string_witness,
    source_string_witness,
    string_context_text_pairs,
    string_witness_value_sets,
)
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.query.planner import symbolic_query
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

logger = get_logger(__name__)
_MAX_STRING_WITNESS_STRINGS = 2
_MAX_STRING_WITNESS_PRODUCT_INTS = 3


def string_integer_witness_model(constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
    """Return a mixed string/int witness when concrete substitution proves SAT."""
    if not _evidence_solvers.evidence_budget_available():
        return None
    try:
        query = symbolic_query(constraints)
        formula = query.conjunction()
        constants = _evidence_cache.witness_constants(formula)
        if (
            not constants.string_variables
            or len(constants.string_variables) > _MAX_STRING_WITNESS_STRINGS
        ):
            return None
        return extract_string_integer_witness(
            formula,
            string_variables=constants.string_variables,
            integer_variables=constants.integer_variables,
            bool_variables=constants.bool_variables,
        )
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("String/integer witness feasibility check failed; treating as inconclusive")
    return None


def string_integer_context_truth_value(
    context_constraints: Sequence[z3.BoolRef],
    query: z3.BoolRef,
) -> bool | None:
    """Return the first deterministic string/int witness truth value for ``query``.

    This helper is for scheduling only. It uses context constraints to collect
    generated string/``ord``/``count`` variables, then substitutes deterministic
    concrete witness candidates into ``query`` alone. It does not prove branch
    feasibility and must never be used to prune a branch.
    """
    if not _evidence_solvers.evidence_budget_available():
        return None
    try:
        constants = _evidence_cache.witness_constants_from_expressions(
            (*context_constraints, query),
        )
        if not constants.string_variables and not constants.integer_variables:
            return None
        if not constants.string_variables and not has_string_context_integers(
            constants.integer_variables,
        ):
            return None
        for substitutions in _string_integer_context_substitutions(constants, query):
            simplified = simplify_expr(z3.substitute(query, *substitutions))
            if z3.is_true(simplified):
                return True
            if z3.is_false(simplified):
                return False
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("String/integer context truth probe failed; skipping branch hint")
    return None


def extract_string_integer_witness(
    formula: z3.BoolRef,
    *,
    string_variables: list[z3.SeqRef],
    integer_variables: list[z3.ArithRef],
    bool_variables: list[z3.BoolRef],
) -> z3.ModelRef | None:
    """Return a string/integer witness for an already simplified formula."""
    if not _evidence_solvers.evidence_budget_available():
        return None
    if not string_variables or len(string_variables) > _MAX_STRING_WITNESS_STRINGS:
        return None
    integer_prefixes = IntegerEqualities.slot_prefixes(integer_variables)
    bool_type_slots = _string_substitutions.bool_type_slots(bool_variables)
    for string_values, active_string_prefixes in string_witness_value_sets(
        string_variables,
        integer_variables,
        formula,
    ):
        for integer_values in _string_integer_assignments(
            integer_variables,
            string_values,
            formula,
        ):
            if not _evidence_solvers.evidence_budget_available():
                return None
            substitutions = _string_substitutions.string_integer_substitutions(
                string_variables=string_variables,
                integer_variables=integer_variables,
                string_values=string_values,
                active_string_prefixes=active_string_prefixes,
                integer_values=integer_values,
                integer_prefixes=integer_prefixes,
                bool_type_slots=bool_type_slots,
            )
            if not z3.is_true(simplify_expr(z3.substitute(formula, *substitutions))):
                continue
            return _witness_models.substitution_model(substitutions)
    return None


def _string_integer_assignments(
    integer_variables: list[z3.ArithRef],
    string_values: tuple[str, ...],
    formula: z3.BoolRef,
) -> list[tuple[int, ...]]:
    if not _evidence_solvers.evidence_budget_available():
        return []
    assignments: list[tuple[int, ...]] = []
    source_text = source_string_witness(string_values)
    bin_text = bin_string_witness(string_values)
    ord_seed = string_context_integer_assignment(
        integer_variables,
        formula=formula,
        source_text=source_text,
        bin_text=bin_text,
    )
    if ord_seed is not None:
        assignments.append(ord_seed)
    if len(integer_variables) > _MAX_STRING_WITNESS_PRODUCT_INTS:
        return assignments
    candidate_groups = [
        IntegerWitnesses.string_context_candidates(
            variable.decl().name(),
            source_text=source_text,
            bin_text=bin_text,
        )
        for variable in integer_variables
    ]
    assignments.extend(itertools.product(*candidate_groups))
    return list(dict.fromkeys(assignments))


def _string_integer_context_substitutions(
    constants: _evidence_cache.WitnessConstants,
    query: z3.BoolRef,
) -> Iterator[list[tuple[z3.ExprRef, z3.ExprRef]]]:
    """Yield deterministic substitutions for scheduling-only branch truth probes."""
    integer_prefixes = IntegerEqualities.slot_prefixes(constants.integer_variables)
    bool_type_slots = _string_substitutions.bool_type_slots(constants.bool_variables)
    if constants.string_variables:
        for string_values, active_string_prefixes in string_witness_value_sets(
            constants.string_variables,
            constants.integer_variables,
            query,
        ):
            for integer_values in _string_integer_assignments(
                constants.integer_variables,
                string_values,
                query,
            ):
                yield _string_substitutions.string_integer_substitutions(
                    string_variables=constants.string_variables,
                    integer_variables=constants.integer_variables,
                    string_values=string_values,
                    active_string_prefixes=active_string_prefixes,
                    integer_values=integer_values,
                    integer_prefixes=integer_prefixes,
                    bool_type_slots=bool_type_slots,
                )
        return

    for source_text, bin_text in string_context_text_pairs(query):
        integer_values = string_context_integer_assignment(
            constants.integer_variables,
            formula=query,
            source_text=source_text,
            bin_text=bin_text,
        )
        if integer_values is None:
            continue
        yield _string_substitutions.string_integer_substitutions(
            string_variables=[],
            integer_variables=constants.integer_variables,
            string_values=(),
            active_string_prefixes=frozenset(),
            integer_values=integer_values,
            integer_prefixes=integer_prefixes,
            bool_type_slots=bool_type_slots,
        )
