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

"""Compile and check call-site contract entry conditions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import UnsupportedReason
from pysymex._internal.contracts.ir.obligations import QueryKind
from pysymex._internal.contracts.runtime.call.condition.clauses import (
    compile_assumption_clause,
    evaluate_precondition_clause,
    merge_unsupported_reasons,
)
from pysymex._internal.contracts.solver.query import ContractQuery, check_contract_query
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    import z3

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.contracts.types import Contract
    from pysymex._internal.core.state.record import VMState

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class CallConditionEvaluation:
    """Compiled call-entry conditions and diagnostics from clause evaluation."""

    issues: tuple[Issue, ...]
    conditions: tuple[z3.BoolRef, ...]
    has_unsupported: bool
    unsupported_reasons: tuple[UnsupportedReason, ...]


def evaluate_call_conditions(
    state: VMState,
    func: Callable[..., object],
    preconditions: Sequence[Contract],
    assumptions: Sequence[Contract],
    symbols: Mapping[str, z3.ExprRef],
) -> CallConditionEvaluation:
    """Compile call-site preconditions and assumptions for a callee entry state."""
    issues: list[Issue] = []
    conditions: list[z3.BoolRef] = []
    has_unsupported = False
    unsupported_reasons: tuple[UnsupportedReason, ...] = ()

    for clause in preconditions:
        clause_result = evaluate_precondition_clause(state, func, clause, symbols)
        if clause_result.condition is not None:
            conditions.append(clause_result.condition)
        if clause_result.issue is not None:
            issues.append(clause_result.issue)
        if clause_result.has_unsupported:
            has_unsupported = True
            unsupported_reasons = merge_unsupported_reasons(
                unsupported_reasons,
                clause_result.unsupported_reasons,
            )

    for clause in assumptions:
        clause_result = compile_assumption_clause(state, func, clause, symbols)
        if clause_result.condition is not None:
            conditions.append(clause_result.condition)
        if clause_result.issue is not None:
            issues.append(clause_result.issue)
        if clause_result.has_unsupported:
            has_unsupported = True
            unsupported_reasons = merge_unsupported_reasons(
                unsupported_reasons,
                clause_result.unsupported_reasons,
            )

    return CallConditionEvaluation(
        issues=tuple(issues),
        conditions=tuple(conditions),
        has_unsupported=has_unsupported,
        unsupported_reasons=unsupported_reasons,
    )


def callee_domain_status(
    state: VMState,
    conditions: Sequence[z3.BoolRef],
) -> tuple[VerificationResult, tuple[UnsupportedReason, ...]]:
    """Return whether the callee entry domain remains satisfiable."""
    if not conditions:
        return VerificationResult.VERIFIED, ()
    query = ContractQuery.from_constraints(
        [*state.path_constraints, *conditions],
        query_kind=QueryKind.CALL_PRECONDITION,
    )
    try:
        result = check_contract_query(query)
    except Exception:
        logger.warning("Callee contract entry-domain check failed", exc_info=True)
        return VerificationResult.UNKNOWN, (UnsupportedReason.SOLVER_FAILURE,)
    if result.is_unsat:
        return VerificationResult.UNREACHABLE, ()
    if result.is_unknown:
        return VerificationResult.UNKNOWN, ()
    return VerificationResult.VERIFIED, ()
