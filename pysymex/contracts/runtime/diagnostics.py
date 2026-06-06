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

"""Diagnostic issue adapters for runtime contract evidence."""

from __future__ import annotations

from collections.abc import Callable

from pysymex.analysis.detectors import Issue, IssueKind, Severity as IssueSeverity
from pysymex.contracts.ir.evidence import EvidenceResult
from pysymex.contracts.runtime.capture import (
    record_runtime_contract_evidence,
    record_runtime_contract_outcome,
)
from pysymex.contracts.types import Contract, Severity as ContractSeverity, VerificationResult
from pysymex.core.state.record import VMState


def issue_severity_for_clause(clause: Contract) -> IssueSeverity:
    """Map a declared contract severity onto the runtime issue severity model."""
    if clause.severity is ContractSeverity.WARNING:
        return IssueSeverity.WARNING
    return IssueSeverity.ERROR


def _unknown_contract_issue(
    *,
    message: str,
    state: VMState,
    severity: IssueSeverity = IssueSeverity.ERROR,
    line_number: int | None = None,
    function_name: str | None = None,
) -> Issue:
    """Build an ``IssueKind.UNKNOWN`` issue for an inconclusive contract check."""
    return Issue(
        kind=IssueKind.UNKNOWN,
        message=message,
        constraints=list(state.path_constraints),
        model=None,
        pc=state.pc,
        line_number=line_number,
        function_name=function_name,
        severity=severity,
    )


def record_diagnostic_issue(
    clause: Contract,
    func: Callable[..., object],
    state: VMState,
    result: VerificationResult,
    message: str,
    *,
    evidence: EvidenceResult | None = None,
) -> Issue:
    """Build and capture an inconclusive or unsupported contract diagnostic."""
    issue = _unknown_contract_issue(
        message=message,
        state=state,
        severity=issue_severity_for_clause(clause),
        line_number=clause.line_number,
        function_name=getattr(func, "__name__", "unknown"),
    )
    if evidence is not None:
        record_runtime_contract_evidence(clause, func, evidence, issue)
    else:
        record_runtime_contract_outcome(clause, func, result, issue)
    return issue


__all__ = ["issue_severity_for_clause", "record_diagnostic_issue"]
