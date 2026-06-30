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

"""Runtime class invariant obligation checks.

This module owns class-invariant predicate lowering, solver queries, and typed
evidence creation. Runtime hooks decide when to call it; report adapters decide
how evidence is shown to users.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.invariants.policy import (
    DEFAULT_INVARIANT_POLICY,
    InvariantCheckPoint,
    InvariantPolicy,
)
from pysymex._internal.contracts.invariants.symbols import (
    compile_invariant_clause,
    invariant_symbol_table,
)
from pysymex._internal.contracts.invariants.targets import InvariantTargets
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
from pysymex._internal.core.state.record import StateConstraints, VMState
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from pysymex._internal.contracts.types import Contract

logger = get_logger(__name__)


def check_class_invariants(
    state: VMState,
    func: Callable[..., object],
    checkpoint: InvariantCheckPoint,
    *,
    policy: InvariantPolicy = DEFAULT_INVARIANT_POLICY,
) -> list[Issue]:
    """Check applicable class invariants at a method entry or exit checkpoint."""
    target = InvariantTargets.for_callable(func, policy=policy)
    if target is None or checkpoint not in target.checkpoints:
        return []

    symbols = invariant_symbol_table(state, func, checkpoint)
    issues: list[Issue] = []
    for clause in target.clauses:
        issues.extend(_check_one_invariant(state, func, clause, checkpoint, symbols))
    return issues


def _check_one_invariant(
    state: VMState,
    func: Callable[..., object],
    clause: Contract,
    checkpoint: InvariantCheckPoint,
    symbols: Mapping[str, z3.ExprRef],
) -> list[Issue]:
    """Check one invariant clause and return any generated diagnostic issue."""
    hook = _hook_for_checkpoint(checkpoint)
    query_kind = _query_kind_for_checkpoint(checkpoint)
    try:
        condition = compile_invariant_clause(clause, symbols)
    except (TypeError, ValueError, z3.Z3Exception) as exc:
        logger.debug("Failed to compile class invariant %s", clause.condition, exc_info=True)
        message = (
            f"Class invariant '{clause.condition}' could not be checked at "
            f"{checkpoint.value}: {exc}"
        )
        evidence = build_contract_evidence(
            clause,
            func,
            hook=hook,
            query_kind=query_kind,
            pc=state.pc,
            status=VerificationResult.UNSUPPORTED,
            solver_status=SolverStatus.UNSUPPORTED,
            message=message,
            query_constraints=list(state.path_constraints),
            unsupported_reasons=unsupported_reasons_for_exception(exc),
        )
        return [
            record_diagnostic_issue(
                clause,
                func,
                state,
                VerificationResult.UNSUPPORTED,
                message,
                evidence=evidence,
            ),
        ]

    constraints = [*state.path_constraints, z3.Not(condition)]
    query = ContractQuery.from_constraints(
        constraints,
        query_kind=query_kind,
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
        need_model=True,
    )
    try:
        result = check_contract_query(query)
    except Exception as exc:
        logger.warning(
            "Class invariant solver check failed for %s",
            clause.condition,
            exc_info=True,
        )
        message = (
            f"Class invariant '{clause.condition}' check at {checkpoint.value} "
            f"was inconclusive: {exc}"
        )
        evidence = build_contract_evidence(
            clause,
            func,
            hook=hook,
            query_kind=query_kind,
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
        return [
            record_diagnostic_issue(
                clause,
                func,
                state,
                VerificationResult.UNKNOWN,
                message,
                evidence=evidence,
            ),
        ]

    if result.is_sat:
        message = f"Class invariant '{clause.condition}' may be violated at {checkpoint.value}"
        evidence = build_contract_evidence(
            clause,
            func,
            hook=hook,
            query_kind=query_kind,
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
            line_number=clause.line_number,
            model=result.model,
            pc=state.pc,
            function_name=getattr(func, "__name__", "unknown"),
            severity=issue_severity_for_clause(clause),
        )
        RuntimeContractOutcome.record_evidence(clause, func, evidence, issue)
        return [issue]

    if result.is_unknown:
        message = (
            f"Class invariant '{clause.condition}' check at {checkpoint.value} returned unknown"
        )
        evidence = build_contract_evidence(
            clause,
            func,
            hook=hook,
            query_kind=query_kind,
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
        return [
            record_diagnostic_issue(
                clause,
                func,
                state,
                VerificationResult.UNKNOWN,
                message,
                evidence=evidence,
            ),
        ]

    evidence = build_contract_evidence(
        clause,
        func,
        hook=hook,
        query_kind=query_kind,
        pc=state.pc,
        status=VerificationResult.VERIFIED,
        solver_status=SolverStatus.UNSAT,
        message=f"Class invariant '{clause.condition}' is verified at {checkpoint.value}",
        formula=condition,
        query_constraints=query.constraints,
        timeout_ms=query.timeout_ms,
        need_model=query.need_model,
        theory_profile=query.theory_profile,
    )
    RuntimeContractOutcome.record_evidence(clause, func, evidence)
    return []


def _hook_for_checkpoint(checkpoint: InvariantCheckPoint) -> ObligationHook:
    """Return the runtime hook that owns *checkpoint* evidence."""
    if checkpoint is InvariantCheckPoint.ENTRY:
        return ObligationHook.FRAME_ENTRY
    return ObligationHook.FRAME_EXIT


def _query_kind_for_checkpoint(checkpoint: InvariantCheckPoint) -> QueryKind:
    """Return the query kind used for one invariant checkpoint."""
    if checkpoint is InvariantCheckPoint.ENTRY:
        return QueryKind.INVARIANT_ENTRY
    return QueryKind.INVARIANT_EXIT
