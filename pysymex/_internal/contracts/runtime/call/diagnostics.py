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

"""Diagnostics for call-site contract obligations blocked before frame entry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex._internal.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex._internal.contracts.obligations.evidence import build_contract_evidence
from pysymex._internal.contracts.runtime.diagnostics import record_diagnostic_issue

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.contracts.types import Contract
    from pysymex._internal.core.state.record import VMState


def binding_failure_diagnostics(
    state: VMState,
    func: Callable[..., object],
    preconditions: Sequence[Contract],
    assumptions: Sequence[Contract],
    postconditions: Sequence[Contract],
    exc: TypeError | ValueError,
) -> list[Issue]:
    """Build call-site diagnostics when Python signature binding fails."""
    issues: list[Issue] = []
    for clause in preconditions:
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
            ),
        )
    issues.extend(
        dependent_postcondition_diagnostics(
            state,
            func,
            postconditions,
            VerificationResult.UNSUPPORTED,
            (UnsupportedReason.UNSUPPORTED_DECLARATION,),
        ),
    )
    for clause in assumptions:
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
            ),
        )
    return issues


def dependent_postcondition_diagnostics(
    state: VMState,
    func: Callable[..., object],
    postconditions: Sequence[Contract],
    status: VerificationResult,
    unsupported_reasons: tuple[UnsupportedReason, ...],
) -> list[Issue]:
    """Build diagnostics for callee postconditions blocked before frame entry."""
    issues: list[Issue] = []
    if status is VerificationResult.VERIFIED:
        return issues
    for clause in postconditions:
        message = _dependent_postcondition_message(clause.condition, status)
        evidence = build_contract_evidence(
            clause,
            func,
            hook=ObligationHook.FRAME_EXIT,
            query_kind=QueryKind.POSTCONDITION,
            pc=state.pc,
            status=status,
            solver_status=_dependent_postcondition_solver_status(status),
            message=message,
            query_constraints=list(state.path_constraints),
            unsupported_reasons=unsupported_reasons,
        )
        issues.append(
            record_diagnostic_issue(
                clause,
                func,
                state,
                status,
                message,
                evidence=evidence,
            ),
        )
    return issues


def _dependent_postcondition_solver_status(status: VerificationResult) -> SolverStatus:
    """Return solver evidence status for callee postconditions blocked at entry."""
    if status is VerificationResult.UNSUPPORTED:
        return SolverStatus.UNSUPPORTED
    if status is VerificationResult.UNREACHABLE:
        return SolverStatus.UNSAT
    return SolverStatus.UNKNOWN


def _dependent_postcondition_message(condition: str, status: VerificationResult) -> str:
    """Return a precise message for a callee postcondition blocked before entry."""
    if status is VerificationResult.UNSUPPORTED:
        return f"Postcondition '{condition}' depends on an unsupported callee entry condition"
    if status is VerificationResult.UNREACHABLE:
        return f"Postcondition '{condition}' is unreachable because callee entry is unsat"
    return f"Postcondition '{condition}' depends on an inconclusive callee entry condition"
