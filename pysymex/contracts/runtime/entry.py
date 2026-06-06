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

"""Frame-entry contract obligations."""

from __future__ import annotations

from collections.abc import Callable

import z3

from pysymex.analysis.detectors import Issue
from pysymex.contracts.binding import collect_current_derived_symbols
from pysymex.contracts.decorators import get_function_contract
from pysymex.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex.contracts.obligations import (
    build_contract_evidence,
    unsupported_reasons_for_exception,
)
from pysymex.contracts.runtime.capture import record_runtime_contract_evidence
from pysymex.contracts.runtime.diagnostics import record_diagnostic_issue
from pysymex.contracts.solver import (
    ContractQuery,
    check_contract_query,
    known_sat_prefix_len_for_state,
)
from pysymex.contracts.types import VerificationResult
from pysymex.contracts.value_expressions import expression_for_contract_value
from pysymex.core.state.record import VMState
from pysymex.logger import get_logger

logger = get_logger(__name__)


def inject_preconditions_initial(
    state: VMState,
    func: Callable[..., object],
    *,
    include_preconditions: bool = True,
    include_postconditions: bool = True,
) -> tuple[VMState, list[Issue], bool]:
    """Inject function entry requirements and trusted assumptions into the state."""
    contract = get_function_contract(func)
    if not contract:
        return state, [], True

    symbols: dict[str, z3.ExprRef] = {}
    issues: list[Issue] = []
    postconditions_supported = True
    for name, stack_val in state.local_vars.items():
        expr = expression_for_contract_value(stack_val)
        if expr is not None:
            symbols[name] = expr
    symbols.update(collect_current_derived_symbols(dict(state.local_vars.items()), state.memory))

    if include_preconditions and contract.preconditions:
        for clause in contract.preconditions:
            try:
                cond = clause.compile(symbols)
            except (TypeError, ValueError, z3.Z3Exception) as exc:
                postconditions_supported = False
                logger.debug("Failed to compile precondition %s", clause.condition, exc_info=True)
                message = f"Precondition '{clause.condition}' could not be checked: {exc}"
                evidence = build_contract_evidence(
                    clause,
                    func,
                    hook=ObligationHook.FRAME_ENTRY,
                    query_kind=QueryKind.ENTRY_SAT,
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
            constraints = list(state.path_constraints) + [cond]
            query = ContractQuery.from_constraints(
                constraints,
                query_kind=QueryKind.ENTRY_SAT,
                known_sat_prefix_len=known_sat_prefix_len_for_state(state),
            )
            try:
                result = check_contract_query(query)
            except Exception as exc:
                message = f"Precondition '{clause.condition}' satisfiability is inconclusive: {exc}"
                evidence = build_contract_evidence(
                    clause,
                    func,
                    hook=ObligationHook.FRAME_ENTRY,
                    query_kind=QueryKind.ENTRY_SAT,
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
            else:
                if result.is_unsat:
                    message = f"Precondition '{clause.condition}' admits no valid entry state"
                    evidence = build_contract_evidence(
                        clause,
                        func,
                        hook=ObligationHook.FRAME_ENTRY,
                        query_kind=QueryKind.ENTRY_SAT,
                        pc=state.pc,
                        status=VerificationResult.UNREACHABLE,
                        solver_status=SolverStatus.UNSAT,
                        message=message,
                        formula=cond,
                        query_constraints=query.constraints,
                        timeout_ms=query.timeout_ms,
                        need_model=query.need_model,
                        theory_profile=query.theory_profile,
                    )
                    issues.append(
                        record_diagnostic_issue(
                            clause,
                            func,
                            state,
                            VerificationResult.UNREACHABLE,
                            message,
                            evidence=evidence,
                        )
                    )
                elif result.is_unknown:
                    message = f"Precondition '{clause.condition}' satisfiability is inconclusive"
                    evidence = build_contract_evidence(
                        clause,
                        func,
                        hook=ObligationHook.FRAME_ENTRY,
                        query_kind=QueryKind.ENTRY_SAT,
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
                else:
                    evidence = build_contract_evidence(
                        clause,
                        func,
                        hook=ObligationHook.FRAME_ENTRY,
                        query_kind=QueryKind.ENTRY_SAT,
                        pc=state.pc,
                        status=VerificationResult.VERIFIED,
                        solver_status=SolverStatus.SAT,
                        message=f"Precondition '{clause.condition}' is satisfiable",
                        formula=cond,
                        query_constraints=query.constraints,
                        timeout_ms=query.timeout_ms,
                        need_model=query.need_model,
                        theory_profile=query.theory_profile,
                    )
                    record_runtime_contract_evidence(clause, func, evidence)
            state = state.add_constraint(cond)

    if contract.assumptions:
        for clause in contract.assumptions:
            try:
                cond = clause.compile(symbols)
                state = state.add_constraint(cond)
            except (TypeError, ValueError, z3.Z3Exception) as exc:
                postconditions_supported = False
                logger.debug("Failed to compile assumption %s", clause.condition, exc_info=True)
                message = f"Assumption '{clause.condition}' could not be modeled: {exc}"
                evidence = build_contract_evidence(
                    clause,
                    func,
                    hook=ObligationHook.FRAME_ENTRY,
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

    if include_postconditions and not postconditions_supported:
        for clause in contract.postconditions:
            message = (
                f"Postcondition '{clause.condition}' depends on an unsupported entry condition"
            )
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
                unsupported_reasons=(UnsupportedReason.PREDICATE_LOWERING,),
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
    return state, issues, postconditions_supported


__all__ = ["inject_preconditions_initial"]
