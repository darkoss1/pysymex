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

"""Configuration and result models for contract-aware verified execution.

``VerifiedExecutionConfig`` mirrors ``ExecutionConfig`` with additional toggles
for contracts, termination, and optional bounded-integer policies.
``VerifiedExecutionResult`` aggregates symbolic issues, contract outcomes,
property proofs, and termination status produced by
:class:`~pysymex.execution.executors.verified.executor.VerifiedExecutor`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict

from pysymex.analysis.detectors import Issue
from pysymex.analysis.static.properties import ProofStatus, PropertyKind, PropertyProof
from pysymex.config.defaults import (
    DEFAULT_DETECT_OVERFLOW,
    DEFAULT_LIMIT_MAX_DEPTH,
    DEFAULT_LIMIT_MAX_ITERATIONS,
    DEFAULT_LIMIT_MAX_PATHS,
    DEFAULT_LIMIT_TIMEOUT_SECONDS,
    DEFAULT_VERIFIED_INTEGER_BITS,
    DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS,
    DEFAULT_VERIFIED_TERMINATION_TIMEOUT_MS,
)
from pysymex.contracts.ir.evidence import EvidenceResult
from pysymex.contracts.types import ContractKind, Severity, VerificationResult
from pysymex.execution.strategies.manager.types import ExplorationStrategy
from pysymex.execution.termination import TerminationProof


@dataclass
class VerifiedExecutionConfig:
    """Configuration for verified symbolic execution."""

    max_paths: int = DEFAULT_LIMIT_MAX_PATHS
    max_depth: int = DEFAULT_LIMIT_MAX_DEPTH
    max_iterations: int = DEFAULT_LIMIT_MAX_ITERATIONS
    timeout_seconds: float = DEFAULT_LIMIT_TIMEOUT_SECONDS
    strategy: ExplorationStrategy = ExplorationStrategy.ADAPTIVE
    max_loop_iterations: int = 10
    unroll_loops: bool = True
    solver_timeout_ms: int = DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS
    check_preconditions: bool = True
    check_postconditions: bool = True
    check_loop_invariants: bool = True
    check_class_invariants: bool = True
    check_termination: bool = False
    termination_timeout_ms: int = DEFAULT_VERIFIED_TERMINATION_TIMEOUT_MS
    check_division_safety: bool = True
    check_array_bounds: bool = True
    integer_bits: int = DEFAULT_VERIFIED_INTEGER_BITS
    infer_properties: bool = False
    detect_division_by_zero: bool = True
    detect_assertion_errors: bool = True
    detect_index_errors: bool = True
    detect_type_errors: bool = True
    # Python ints are unbounded; bounded-overflow checks are an explicit policy.
    detect_overflow: bool = DEFAULT_DETECT_OVERFLOW
    verbose: bool = False
    collect_coverage: bool = True
    symbolic_args: dict[str, str] = field(default_factory=dict[str, str])

    @property
    def bounded_overflow_enabled(self) -> bool:
        """Return whether bounded-width integer diagnostics were explicitly requested."""
        return self.detect_overflow


class VerifiedExecutionOverrides(TypedDict, total=False):
    """Typed keyword overrides accepted by ``verify``."""

    max_paths: int
    max_depth: int
    max_iterations: int
    timeout_seconds: float
    strategy: ExplorationStrategy
    max_loop_iterations: int
    unroll_loops: bool
    solver_timeout_ms: int
    check_preconditions: bool
    check_postconditions: bool
    check_loop_invariants: bool
    check_class_invariants: bool
    check_termination: bool
    termination_timeout_ms: int
    check_division_safety: bool
    check_array_bounds: bool
    integer_bits: int
    infer_properties: bool
    detect_division_by_zero: bool
    detect_assertion_errors: bool
    detect_index_errors: bool
    detect_type_errors: bool
    detect_overflow: bool
    verbose: bool
    collect_coverage: bool


@dataclass
class ContractIssue:
    """A contract-related issue found during execution."""

    kind: ContractKind
    condition: str
    message: str
    line_number: int | None = None
    function_name: str | None = None
    counterexample: dict[str, object] = field(default_factory=dict[str, object])
    severity: Severity = Severity.ERROR
    result: VerificationResult = VerificationResult.VIOLATED
    evidence: EvidenceResult | None = None

    def format(self) -> str:
        """Format for display."""
        location = f" at line {self.line_number}" if self.line_number else ""
        func = f" in {self.function_name}" if self.function_name else ""
        status = self.result.name
        warning = "[WARNING] " if self.severity is Severity.WARNING else ""
        result = f"[{status}] {warning}{self.kind.name}{func}{location}: {self.message}\n"
        result += f"  Condition: {self.condition}\n"
        if self.counterexample:
            result += "  Counterexample:\n"
            for var, val in self.counterexample.items():
                result += f"    {var} = {val}\n"
        return result


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
            if self.termination_proof.ranking_function:
                lines.append(f"  Ranking: {self.termination_proof.ranking_function.expression}")
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
