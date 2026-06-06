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

"""Evaluate callee preconditions and assumptions at call sites.

Binds call arguments to the callee signature, compiles ``@requires`` clauses, queries
:mod:`pysymex.core.solver` for feasible violations, and adds satisfied preconditions and
``@assumes`` constraints to the caller :class:`~pysymex.core.state.record.VMState`. Returns
``None`` for the state when any clause cannot be compiled. Frame-entry checks live in
:mod:`pysymex.contracts.runtime.entry`.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.contracts.decorators import get_function_contract
from pysymex.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex.contracts.runtime.diagnostics import (
    issue_severity_for_clause,
    record_diagnostic_issue,
)
from pysymex.contracts.obligations import (
    build_contract_evidence,
    unsupported_reasons_for_exception,
)
from pysymex.contracts.runtime.capture import record_runtime_contract_evidence
from pysymex.contracts.solver import ContractQuery, check_contract_query
from pysymex.contracts.types import VerificationResult
from pysymex.contracts.value_expressions import expression_for_contract_value
from pysymex.core.state.record import VMState
from pysymex.logger import get_logger

logger = get_logger(__name__)


def inject_call_preconditions(
    state: VMState,
    func: Callable[..., object],
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    *,
    include_preconditions: bool = True,
) -> tuple[VMState | None, list[Issue]]:
    """Verify callee preconditions and return the constrained entry state."""
    contract = get_function_contract(func)
    if not contract:
        return state, []
    enabled_preconditions = contract.preconditions if include_preconditions else []
    if not enabled_preconditions and not contract.assumptions:
        return state, []

    try:
        bound = inspect.signature(func).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = bound.arguments
    except (TypeError, ValueError) as exc:
        issues = []
        for clause in enabled_preconditions:
            message = f"Precondition '{clause.condition}' could not be checked: {exc}"
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
                unsupported_reasons=(UnsupportedReason.UNSUPPORTED_DECLARATION,),
            )
            issues.append(
                record_diagnostic_issue(
                    clause,
                    func,
                    state,
                    VerificationResult.UNSUPPORTED,
                    message,
                    evidence=evidence,
                )
            )
        for clause in contract.assumptions:
            message = f"Assumption '{clause.condition}' could not be modeled: {exc}"
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
                unsupported_reasons=(UnsupportedReason.UNSUPPORTED_DECLARATION,),
            )
            issues.append(
                record_diagnostic_issue(
                    clause,
                    func,
                    state,
                    VerificationResult.UNSUPPORTED,
                    message,
                    evidence=evidence,
                )
            )
        return None, issues

    symbols: dict[str, z3.ExprRef] = {}
    for name, stack_val in arguments.items():
        expr = expression_for_contract_value(stack_val)
        if expr is not None:
            symbols[name] = expr

    issues: list[Issue] = []
    conditions: list[z3.BoolRef] = []
    has_unsupported = False
    for clause in enabled_preconditions:
        try:
            cond = clause.compile(symbols)
        except (TypeError, ValueError, z3.Z3Exception) as exc:
            has_unsupported = True
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
                unsupported_reasons=unsupported_reasons_for_exception(exc),
            )
            issues.append(
                record_diagnostic_issue(
                    clause,
                    func,
                    state,
                    VerificationResult.UNSUPPORTED,
                    message,
                    evidence=evidence,
                )
            )
            continue

        conditions.append(cond)
        constraints = list(state.path_constraints) + [z3.Not(cond)]
        query = ContractQuery.from_constraints(
            constraints,
            query_kind=QueryKind.CALL_PRECONDITION,
            need_model=True,
        )
        try:
            res = check_contract_query(query)
        except Exception as exc:
            logger.warning(
                "Precondition solver check failed for %s", clause.condition, exc_info=True
            )
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
                formula=cond,
                query_constraints=query.constraints,
                unsupported_reasons=(UnsupportedReason.SOLVER_FAILURE,),
                timeout_ms=query.timeout_ms,
                need_model=query.need_model,
                theory_profile=query.theory_profile,
            )
            issues.append(
                record_diagnostic_issue(
                    clause,
                    func,
                    state,
                    VerificationResult.UNKNOWN,
                    message,
                    evidence=evidence,
                )
            )
            continue
        if res.is_sat:
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
                formula=cond,
                query_constraints=query.constraints,
                model=res.model,
                timeout_ms=query.timeout_ms,
                need_model=query.need_model,
                theory_profile=query.theory_profile,
            )
            issue = Issue(
                kind=IssueKind.CONTRACT_VIOLATION,
                message=message,
                constraints=constraints,
                model=res.model,
                pc=state.pc,
                line_number=clause.line_number,
                function_name=getattr(func, "__name__", "unknown"),
                severity=issue_severity_for_clause(clause),
            )
            record_runtime_contract_evidence(clause, func, evidence, issue)
            issues.append(issue)
        elif res.is_unknown:
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
                formula=cond,
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
            record_runtime_contract_evidence(clause, func, evidence, issue)
            issues.append(issue)
        else:
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
                formula=cond,
                query_constraints=query.constraints,
                timeout_ms=query.timeout_ms,
                need_model=query.need_model,
                theory_profile=query.theory_profile,
            )
            record_runtime_contract_evidence(clause, func, evidence)

    for clause in contract.assumptions:
        try:
            conditions.append(clause.compile(symbols))
        except (TypeError, ValueError, z3.Z3Exception) as exc:
            has_unsupported = True
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
                unsupported_reasons=unsupported_reasons_for_exception(exc),
            )
            issues.append(
                record_diagnostic_issue(
                    clause,
                    func,
                    state,
                    VerificationResult.UNSUPPORTED,
                    message,
                    evidence=evidence,
                )
            )

    if has_unsupported:
        return None, issues
    for condition in conditions:
        state = state.add_constraint(condition)
    return state, issues


__all__ = ["inject_call_preconditions"]
