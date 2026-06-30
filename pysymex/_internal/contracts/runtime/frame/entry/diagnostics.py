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

"""Frame-entry diagnostics for dependent postconditions."""

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


def dominant_postcondition_block(
    current: VerificationResult | None,
    candidate: VerificationResult,
) -> VerificationResult:
    """Return the strongest entry-condition block for dependent postconditions."""
    if current is None:
        return candidate
    priority = {
        VerificationResult.UNREACHABLE: 1,
        VerificationResult.UNKNOWN: 2,
        VerificationResult.UNSUPPORTED: 3,
    }
    return candidate if priority[candidate] > priority[current] else current


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


def dependent_postcondition_diagnostics(
    state: VMState,
    func: Callable[..., object],
    postconditions: Sequence[Contract],
    status: VerificationResult,
    unsupported_reasons: tuple[UnsupportedReason, ...],
) -> list[Issue]:
    """Build diagnostics for postconditions blocked by invalid entry evidence."""
    issues: list[Issue] = []
    solver_status = _dependent_postcondition_solver_status(status)
    for clause_obj in postconditions:
        message = _dependent_postcondition_message(clause_obj.condition, status)
        evidence = build_contract_evidence(
            clause_obj,
            func,
            hook=ObligationHook.FRAME_EXIT,
            query_kind=QueryKind.POSTCONDITION,
            pc=state.pc,
            status=status,
            solver_status=solver_status,
            message=message,
            query_constraints=list(state.path_constraints),
            unsupported_reasons=unsupported_reasons,
        )
        issues.append(
            record_diagnostic_issue(
                clause_obj,
                func,
                state,
                status,
                message,
                evidence=evidence,
            ),
        )
    return issues


def _dependent_postcondition_solver_status(status: VerificationResult) -> SolverStatus:
    """Return solver evidence status for postconditions blocked at entry."""
    if status is VerificationResult.UNSUPPORTED:
        return SolverStatus.UNSUPPORTED
    if status is VerificationResult.UNREACHABLE:
        return SolverStatus.UNSAT
    return SolverStatus.UNKNOWN


def _dependent_postcondition_message(condition: str, status: VerificationResult) -> str:
    """Return a precise message for a postcondition blocked by entry evidence."""
    if status is VerificationResult.UNSUPPORTED:
        return f"Postcondition '{condition}' depends on an unsupported entry condition"
    if status is VerificationResult.UNREACHABLE:
        return f"Postcondition '{condition}' is unreachable because entry conditions are unsat"
    return f"Postcondition '{condition}' depends on an inconclusive entry condition"
