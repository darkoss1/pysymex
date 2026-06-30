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

"""Result models for contract-aware verified execution.

``VerifiedExecutionResult`` aggregates symbolic issues, contract outcomes,
property proofs, and termination status produced by
:class:`~pysymex._internal.execution.executors.verified.executor.VerifiedExecutor`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.contracts.ir.evidence import EvidenceResult
from pysymex._internal.contracts.reports.issues import ContractIssue
from pysymex._internal.execution.executors.verified.properties.types import (
    ProofStatus,
    PropertyKind,
    PropertyProof,
)

if TYPE_CHECKING:
    from pysymex._internal.execution.termination import TerminationProof


@dataclass
class ArithmeticIssue:
    """An arithmetic safety issue found during execution."""

    kind: str
    expression: str
    message: str
    line_number: int | None = None
    counterexample: dict[str, object] = field(default_factory=dict[str, object])

    def format(self) -> str:
        """Format for display."""
        location = f" at line {self.line_number}" if self.line_number else ""
        result = f"[ARITHMETIC] {self.kind.upper()}{location}: {self.message}\n"
        result += f"  Expression: {self.expression}\n"
        if self.counterexample:
            result += "  Counterexample:\n"
            for var, val in self.counterexample.items():
                result += f"    {var} = {val}\n"
        return result


@dataclass
class InferredProperty:
    """A property inferred from execution traces."""

    kind: PropertyKind
    description: str
    confidence: float
    proof: PropertyProof | None = None


@dataclass
class VerifiedExecutionResult:
    """Result of verified symbolic execution."""

    issues: list[Issue] = field(default_factory=list[Issue])
    paths_explored: int = 0
    paths_completed: int = 0
    paths_pruned: int = 0
    coverage: set[int] = field(default_factory=set[int])
    total_time_seconds: float = 0.0
    function_name: str = ""
    source_file: str = ""
    contract_issues: list[ContractIssue] = field(default_factory=list[ContractIssue])
    contract_evidence: list[EvidenceResult] = field(default_factory=list[EvidenceResult])
    contracts_checked: int = 0
    contracts_verified: int = 0
    contracts_violated: int = 0
    arithmetic_issues: list[ArithmeticIssue] = field(default_factory=list[ArithmeticIssue])
    termination_proof: TerminationProof | None = None
    inferred_properties: list[InferredProperty] = field(default_factory=list[InferredProperty])
    degraded_passes: list[str] = field(default_factory=list[str])

    @property
    def is_verified(self) -> bool:
        """Check if function is fully verified."""
        return (
            len(self.issues) == 0
            and len(self.contract_issues) == 0
            and len(self.arithmetic_issues) == 0
            and len(self.degraded_passes) == 0
        )

    @property
    def has_issues(self) -> bool:
        """Check if any issues were found."""
        return (
            len(self.issues) > 0 or len(self.contract_issues) > 0 or len(self.arithmetic_issues) > 0
        )

    def format_summary(self) -> str:
        """Format a summary of results."""
        lines = [
            f"Verified Execution: {self.function_name}",
            "=" * 50,
            f"Paths: {self.paths_explored} explored, {self.paths_completed} completed",
            f"Time: {self.total_time_seconds:.2f}s",
            "",
            "Contracts:",
            f"  Checked: {self.contracts_checked}",
            f"  Verified: {self.contracts_verified}",
            f"  Violated: {self.contracts_violated}",
        ]
        if self.termination_proof:
            lines.append("")
            lines.append(f"Termination: {self.termination_proof.status.name}")
            ranking_expression = getattr(
                self.termination_proof.ranking_function,
                "expression",
                None,
            )
            if ranking_expression is not None:
                lines.append(f"  Ranking: {ranking_expression}")
        if self.degraded_passes:
            lines.append("")
            lines.append(f"Analysis degraded: {', '.join(self.degraded_passes)}")
        if self.issues or self.contract_issues or self.arithmetic_issues:
            lines.append("")
            lines.append("Issues Found:")
            for issue in self.issues:
                lines.append(f"  - [{issue.kind.name}] {issue.message}")
            for issue in self.contract_issues:
                lines.append(f"  - [{issue.kind.name}] {issue.message}")
            for issue in self.arithmetic_issues:
                lines.append(f"  - [{issue.kind}] {issue.message}")
        elif self.degraded_passes:
            lines.append("")
            lines.append("No findings reported; analysis was degraded.")
        else:
            lines.append("")
            lines.append("✓ No issues found")
        if self.inferred_properties:
            lines.append("")
            lines.append("Inferred Properties:")
            for prop in self.inferred_properties:
                status = "✓" if prop.proof and prop.proof.status == ProofStatus.PROVEN else "?"
                lines.append(f"  {status} {prop.description}")
        return "\n".join(lines)
