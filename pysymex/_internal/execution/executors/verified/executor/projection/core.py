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

"""Core execution-result projection for verified execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.reports.summary import aggregate_runtime_outcomes
from pysymex._internal.execution.executors.verified.executor.projection.arithmetic import (
    is_projectable_arithmetic_issue,
    project_arithmetic_issue,
)
from pysymex._internal.execution.executors.verified.executor.projection.contracts import (
    is_adjacent_contract_unknown,
    project_unknown_contract_issue,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.contracts.ir.evidence import EvidenceResult
    from pysymex._internal.contracts.reports.issues import ContractIssue
    from pysymex._internal.contracts.runtime.capture import RuntimeContractOutcome
    from pysymex._internal.execution.executors.verified.executor.contracts import (
        VerifiedContractPlan,
    )
    from pysymex._internal.execution.executors.verified.types import ArithmeticIssue
    from pysymex._internal.execution.results.result import ExecutionResult


@dataclass(frozen=True, slots=True)
class VerifiedCoreProjection:
    """Verified-execution fields derived from the core symbolic execution result."""

    issues: list[Issue]
    contract_issues: list[ContractIssue]
    contract_evidence: list[EvidenceResult]
    contracts_checked: int
    contracts_verified: int
    contracts_violated: int
    arithmetic_issues: list[ArithmeticIssue]
    coverage: set[int]
    paths_explored: int
    paths_completed: int
    paths_pruned: int
    total_time_seconds: float
    degraded_passes: list[str]


def project_core_execution_result(
    *,
    core_result: ExecutionResult,
    runtime_contract_outcomes: list[RuntimeContractOutcome],
    unwrapped_func: Callable[..., object],
    contract_plan: VerifiedContractPlan,
) -> VerifiedCoreProjection:
    """Project core execution and runtime-contract outcomes into verified fields."""
    contract_issues: list[ContractIssue] = list(contract_plan.contract_issues)
    contracts_checked = contract_plan.contracts_checked
    arithmetic_issues: list[ArithmeticIssue] = []
    issues: list[Issue] = []
    contract_evidence: list[EvidenceResult] = []
    degraded_passes = list(core_result.degraded_passes)
    runtime_summary = aggregate_runtime_outcomes(
        runtime_contract_outcomes,
        id(unwrapped_func),
        degraded_passes=degraded_passes,
    )
    contract_issues.extend(runtime_summary.issues)
    contract_evidence = runtime_summary.evidence
    contracts_checked += runtime_summary.nested_contract_count
    contracts_verified = runtime_summary.verified_count
    captured_issue_ids = {
        id(outcome.issue) for outcome in runtime_contract_outcomes if outcome.issue is not None
    }

    for issue in core_result.issues:
        if id(issue) in captured_issue_ids:
            continue
        if is_projectable_arithmetic_issue(issue):
            arithmetic_issues.append(project_arithmetic_issue(issue))
        elif issue.kind.name == "CONTRACT_VIOLATION":
            continue
        elif is_adjacent_contract_unknown(issue):
            projected_contract_issue = project_unknown_contract_issue(issue)
            if projected_contract_issue is not None:
                contract_issues.append(projected_contract_issue)
        else:
            issues.append(issue)

    contracts_violated = sum(
        issue.result is VerificationResult.VIOLATED for issue in contract_issues
    )
    return VerifiedCoreProjection(
        issues=issues,
        contract_issues=contract_issues,
        contract_evidence=contract_evidence,
        contracts_checked=contracts_checked,
        contracts_verified=contracts_verified,
        contracts_violated=contracts_violated,
        arithmetic_issues=arithmetic_issues,
        coverage=core_result.coverage,
        paths_explored=core_result.paths_explored,
        paths_completed=core_result.paths_completed,
        paths_pruned=core_result.paths_pruned,
        total_time_seconds=core_result.total_time_seconds,
        degraded_passes=degraded_passes,
    )
