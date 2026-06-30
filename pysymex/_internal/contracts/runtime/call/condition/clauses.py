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

"""Clause-level evaluation for call-site contract conditions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex._internal.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex._internal.contracts.obligations.evidence import (
    build_contract_evidence,
    unsupported_reasons_for_exception,
)
from pysymex._internal.contracts.runtime.capture import RuntimeContractOutcome
from pysymex._internal.contracts.runtime.diagnostics import (
    issue_severity_for_clause,
    record_diagnostic_issue,
)
from pysymex._internal.contracts.solver.query import ContractQuery, check_contract_query
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from pysymex._internal.contracts.types import Contract
    from pysymex._internal.core.state.record import VMState

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class CallClauseEvaluation:
    """Single call-site contract clause result."""

    issue: Issue | None
    condition: z3.BoolRef | None
    has_unsupported: bool
    unsupported_reasons: tuple[UnsupportedReason, ...] = ()


def evaluate_precondition_clause(
    state: VMState,
    func: Callable[..., object],
    clause: Contract,
    symbols: Mapping[str, z3.ExprRef],
) -> CallClauseEvaluation:
    """Compile and check one call-site precondition clause."""
    try:
        condition = clause.compile(symbols)
    except (TypeError, ValueError, z3.Z3Exception) as exc:
        clause_reasons = unsupported_reasons_for_exception(exc)
        logger.debug("Failed to compile call precondition %s", clause.condition, exc_info=True)
        message = (
            f"Precondition '{clause.condition}' of "
            f"{getattr(func, '__name__', 'unknown')} could not be checked: {exc}"
        )
        evidence = build_contract_evidence(
            clause,
            func,
            hook=ObligationHook.CALL_SITE,
            query_kind=QueryKind.CALL_PRECONDITION,
            pc=state.pc,
            status=VerificationResult.UNSUPPORTED,
            solver_status=SolverStatus.UNSUPPORTED,
            message=message,
            query_constraints=list(state.path_constraints),
            unsupported_reasons=clause_reasons,
        )
        return CallClauseEvaluation(
            issue=record_diagnostic_issue(
                clause,
                func,
                state,
                VerificationResult.UNSUPPORTED,
                message,
                evidence=evidence,
            ),
            condition=None,
            has_unsupported=True,
            unsupported_reasons=clause_reasons,
        )

    constraints = [*list(state.path_constraints), z3.Not(condition)]
    query = ContractQuery.from_constraints(
        constraints,
        query_kind=QueryKind.CALL_PRECONDITION,
        need_model=True,
    )
    try:
        result = check_contract_query(query)
    except Exception as exc:
        logger.warning("Precondition solver check failed for %s", clause.condition, exc_info=True)
        message = (
            f"Precondition '{clause.condition}' of "
            f"{getattr(func, '__name__', 'unknown')} check was inconclusive: {exc}"
        )
        evidence = build_contract_evidence(
            clause,
            func,
            hook=ObligationHook.CALL_SITE,
            query_kind=QueryKind.CALL_PRECONDITION,
            pc=state.pc,
            status=VerificationResult.UNKNOWN,
            solver_status=SolverStatus.ERROR,
            message=message,
            formula=condition,
            query_constraints=query.constraints,
            unsupported_reasons=(UnsupportedReason.SOLVER_FAILURE,),
            timeout_ms=query.timeout_ms,
            need_model=query.need_model,
            theory_profile=query.theory_profile,
        )
        return CallClauseEvaluation(
            issue=record_diagnostic_issue(
                clause,
                func,
                state,
                VerificationResult.UNKNOWN,
                message,
                evidence=evidence,
            ),
            condition=condition,
            has_unsupported=False,
        )

    if result.is_sat:
        message = (
            f"Precondition '{clause.condition}' of "
            f"{getattr(func, '__name__', 'unknown')} may be violated"
        )
        evidence = build_contract_evidence(
            clause,
            func,
            hook=ObligationHook.CALL_SITE,
            query_kind=QueryKind.CALL_PRECONDITION,
            pc=state.pc,
            status=VerificationResult.VIOLATED,
            solver_status=SolverStatus.SAT,
            message=message,
            formula=condition,
            query_constraints=query.constraints,
            model=result.model,
            timeout_ms=query.timeout_ms,
            need_model=query.need_model,
            theory_profile=query.theory_profile,
        )
        issue = Issue(
            kind=IssueKind.CONTRACT_VIOLATION,
            message=message,
            constraints=constraints,
            model=result.model,
            pc=state.pc,
            line_number=clause.line_number,
            function_name=getattr(func, "__name__", "unknown"),
            severity=issue_severity_for_clause(clause),
        )
        RuntimeContractOutcome.record_evidence(clause, func, evidence, issue)
        return CallClauseEvaluation(
            issue=issue,
            condition=condition,
            has_unsupported=False,
        )

    if result.is_unknown:
        message = (
            f"Precondition '{clause.condition}' of "
            f"{getattr(func, '__name__', 'unknown')} check returned unknown "
            "(timeout or complex theories)"
        )
        evidence = build_contract_evidence(
            clause,
            func,
            hook=ObligationHook.CALL_SITE,
            query_kind=QueryKind.CALL_PRECONDITION,
            pc=state.pc,
            status=VerificationResult.UNKNOWN,
            solver_status=SolverStatus.UNKNOWN,
            message=message,
            formula=condition,
            query_constraints=query.constraints,
            timeout_ms=query.timeout_ms,
            need_model=query.need_model,
            theory_profile=query.theory_profile,
        )
        issue = Issue(
            kind=IssueKind.UNKNOWN,
            message=message,
            constraints=constraints,
            model=None,
            pc=state.pc,
            line_number=clause.line_number,
            function_name=getattr(func, "__name__", "unknown"),
            severity=issue_severity_for_clause(clause),
        )
        RuntimeContractOutcome.record_evidence(clause, func, evidence, issue)
        return CallClauseEvaluation(
            issue=issue,
            condition=condition,
            has_unsupported=False,
        )

    evidence = build_contract_evidence(
        clause,
        func,
        hook=ObligationHook.CALL_SITE,
        query_kind=QueryKind.CALL_PRECONDITION,
        pc=state.pc,
        status=VerificationResult.VERIFIED,
        solver_status=SolverStatus.UNSAT,
        message=(
            f"Precondition '{clause.condition}' of "
            f"{getattr(func, '__name__', 'unknown')} is verified"
        ),
        formula=condition,
        query_constraints=query.constraints,
        timeout_ms=query.timeout_ms,
        need_model=query.need_model,
        theory_profile=query.theory_profile,
    )
    RuntimeContractOutcome.record_evidence(clause, func, evidence)
    return CallClauseEvaluation(
        issue=None,
        condition=condition,
        has_unsupported=False,
    )


def compile_assumption_clause(
    state: VMState,
    func: Callable[..., object],
    clause: Contract,
    symbols: Mapping[str, z3.ExprRef],
) -> CallClauseEvaluation:
    """Compile one call-site assumption clause."""
    try:
        return CallClauseEvaluation(
            issue=None,
            condition=clause.compile(symbols),
            has_unsupported=False,
        )
    except (TypeError, ValueError, z3.Z3Exception) as exc:
        clause_reasons = unsupported_reasons_for_exception(exc)
        logger.debug("Failed to compile callee assumption %s", clause.condition, exc_info=True)
        message = (
            f"Assumption '{clause.condition}' of "
            f"{getattr(func, '__name__', 'unknown')} could not be modeled: {exc}"
        )
        evidence = build_contract_evidence(
            clause,
            func,
            hook=ObligationHook.CALL_SITE,
            query_kind=QueryKind.ASSUMPTION,
            pc=state.pc,
            status=VerificationResult.UNSUPPORTED,
            solver_status=SolverStatus.UNSUPPORTED,
            message=message,
            query_constraints=list(state.path_constraints),
            unsupported_reasons=clause_reasons,
        )
        return CallClauseEvaluation(
            issue=record_diagnostic_issue(
                clause,
                func,
                state,
                VerificationResult.UNSUPPORTED,
                message,
                evidence=evidence,
            ),
            condition=None,
            has_unsupported=True,
            unsupported_reasons=clause_reasons,
        )


def merge_unsupported_reasons(
    existing: tuple[UnsupportedReason, ...],
    new_reasons: tuple[UnsupportedReason, ...],
) -> tuple[UnsupportedReason, ...]:
    """Merge unsupported reasons while preserving first-seen order."""
    merged = list(existing)
    for reason in new_reasons:
        if reason not in merged:
            merged.append(reason)
    return tuple(merged)
