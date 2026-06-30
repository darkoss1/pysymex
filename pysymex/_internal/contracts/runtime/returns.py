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

"""Frame-exit contract obligations."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.contracts.binding.snapshots import (
    collect_current_derived_symbols,
    collect_result_derived_symbols,
)
from pysymex._internal.contracts.decorator.registry import ContractRegistry
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
from pysymex._internal.contracts.value.expressions import expression_for_contract_value
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import StateConstraints, VMState
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

logger = get_logger(__name__)


def inject_postconditions(
    state: VMState,
    func: Callable[..., object],
    return_value: object,
    config: object,
    *,
    old_symbols: Mapping[str, z3.ExprRef] | None = None,
) -> list[Issue]:
    """Verify function postconditions against the final path state."""
    contract = ContractRegistry.get(func)
    if not contract or not contract.postconditions:
        return []

    symbols: dict[str, z3.ExprRef] = {}
    for name, stack_val in state.local_vars.items():
        expr = expression_for_contract_value(stack_val)
        if expr is not None:
            symbols[name] = expr
    symbols.update(collect_current_derived_symbols(dict(state.local_vars.items()), state.memory))

    ret_expr = expression_for_contract_value(return_value)
    if ret_expr is not None:
        symbols["return"] = ret_expr
        symbols["__return__"] = ret_expr
        symbols["__result__"] = ret_expr
        symbols["result"] = ret_expr
    symbols.update(collect_result_derived_symbols(return_value, state.memory))
    if old_symbols:
        symbols.update(old_symbols)

    issues: list[Issue] = []

    for clause in contract.postconditions:
        try:
            cond = clause.compile(symbols)
        except (TypeError, ValueError, z3.Z3Exception) as exc:
            logger.debug("Failed to compile postcondition %s", clause.condition, exc_info=True)
            message = f"Postcondition '{clause.condition}' could not be checked: {exc}"
            evidence = build_contract_evidence(
                clause,
                func,
                hook=ObligationHook.FRAME_EXIT,
                query_kind=QueryKind.POSTCONDITION,
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
                ),
            )
            continue

        constraints = [*list(state.path_constraints), z3.Not(cond)]
        query = ContractQuery.from_constraints(
            constraints,
            query_kind=QueryKind.POSTCONDITION,
            known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
            need_model=True,
        )
        try:
            res = check_contract_query(query)
        except Exception as exc:
            logger.warning(
                "Postcondition solver check failed for %s",
                clause.condition,
                exc_info=True,
            )
            message = f"Postcondition '{clause.condition}' check was inconclusive: {exc}"
            evidence = build_contract_evidence(
                clause,
                func,
                hook=ObligationHook.FRAME_EXIT,
                query_kind=QueryKind.POSTCONDITION,
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
                ),
            )
            continue
        if res.is_sat:
            message = f"Postcondition '{clause.condition}' may be violated"
            evidence = build_contract_evidence(
                clause,
                func,
                hook=ObligationHook.FRAME_EXIT,
                query_kind=QueryKind.POSTCONDITION,
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
                line_number=clause.line_number,
                model=res.model,
                pc=state.pc,
                function_name=getattr(func, "__name__", "unknown"),
                severity=issue_severity_for_clause(clause),
            )
            RuntimeContractOutcome.record_evidence(clause, func, evidence, issue)
            issues.append(issue)
        elif res.is_unknown:
            message = (
                f"Postcondition '{clause.condition}' check returned unknown "
                "(timeout or complex theories)"
            )
            evidence = build_contract_evidence(
                clause,
                func,
                hook=ObligationHook.FRAME_EXIT,
                query_kind=QueryKind.POSTCONDITION,
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
                line_number=clause.line_number,
                model=None,
                pc=state.pc,
                function_name=getattr(func, "__name__", "unknown"),
                severity=issue_severity_for_clause(clause),
            )
            RuntimeContractOutcome.record_evidence(clause, func, evidence, issue)
            issues.append(issue)
        else:
            evidence = build_contract_evidence(
                clause,
                func,
                hook=ObligationHook.FRAME_EXIT,
                query_kind=QueryKind.POSTCONDITION,
                pc=state.pc,
                status=VerificationResult.VERIFIED,
                solver_status=SolverStatus.UNSAT,
                message=f"Postcondition '{clause.condition}' is verified",
                formula=cond,
                query_constraints=query.constraints,
                timeout_ms=query.timeout_ms,
                need_model=query.need_model,
                theory_profile=query.theory_profile,
            )
            RuntimeContractOutcome.record_evidence(clause, func, evidence)

    return issues
