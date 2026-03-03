"""Data models for verified symbolic execution.

Provides:
- VerifiedExecutionConfig: All configuration knobs
- ContractIssue: A contract-related issue found during execution
- ArithmeticIssue: An arithmetic safety issue
- InferredProperty: A property inferred from execution traces
- VerifiedExecutionResult: Full result of a verified execution run
"""

from __future__ import annotations


from dataclasses import dataclass, field

from typing import Any


from pysymex.analysis.contracts import ContractKind, VerificationResult

from pysymex.analysis.path_manager import ExplorationStrategy

from pysymex.analysis.properties import (
    PropertyKind,
    PropertyProof,
    ProofStatus,
)

from pysymex.analysis.detectors import Issue


from .termination import TerminationProof


@dataclass
class VerifiedExecutionConfig:
    """Configuration for verified symbolic execution."""

    max_paths: int = 1000

    max_depth: int = 100

    max_iterations: int = 10000

    timeout_seconds: float = 60.0

    strategy: ExplorationStrategy = ExplorationStrategy.DFS

    max_loop_iterations: int = 10

    unroll_loops: bool = True

    solver_timeout_ms: int = 5000

    check_preconditions: bool = True

    check_postconditions: bool = True

    check_loop_invariants: bool = True

    check_class_invariants: bool = True

    check_termination: bool = False

    termination_timeout_ms: int = 10000

    check_overflow: bool = True

    check_division_safety: bool = True

    check_array_bounds: bool = True

    integer_bits: int = 64

    infer_properties: bool = False

    detect_division_by_zero: bool = True

    detect_assertion_errors: bool = True

    detect_index_errors: bool = True

    detect_type_errors: bool = True

    detect_overflow: bool = True

    verbose: bool = False

    collect_coverage: bool = True

    symbolic_args: dict[str, str] = field(default_factory=dict[str, str])


@dataclass
class ContractIssue:
    """A contract-related issue found during execution."""

    kind: ContractKind

    condition: str

    message: str

    line_number: int | None = None

    function_name: str | None = None

    counterexample: dict[str, Any] = field(default_factory=dict[str, Any])

    result: VerificationResult = VerificationResult.VIOLATED

    def format(self) -> str:
        """Format for display."""

        location = f" at line {self.line_number}" if self.line_number else ""

        func = f" in {self.function_name}" if self.function_name else ""

        status = self.result.name

        result = f"[{status}] {self.kind.name}{func}{location}: {self.message}\n"

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

    counterexample: dict[str, Any] = field(default_factory=dict[str, Any])

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

    contracts_checked: int = 0

    contracts_verified: int = 0

    contracts_violated: int = 0

    arithmetic_issues: list[ArithmeticIssue] = field(default_factory=list[ArithmeticIssue])

    termination_proof: TerminationProof | None = None

    inferred_properties: list[InferredProperty] = field(default_factory=list[InferredProperty])

    @property
    def is_verified(self) -> bool:
        """Check if function is fully verified."""

        return (
            len(self.issues) == 0
            and len(self.contract_issues) == 0
            and len(self.arithmetic_issues) == 0
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

        if self.issues or self.contract_issues or self.arithmetic_issues:
            lines.append("")

            lines.append("Issues Found:")

            for issue in self.issues:
                lines.append(f"  - [{issue.kind.name}] {issue.message}")

            for issue in self.contract_issues:
                lines.append(f"  - [{issue.kind.name}] {issue.message}")

            for issue in self.arithmetic_issues:
                lines.append(f"  - [{issue.kind}] {issue.message}")

        else:
            lines.append("")

            lines.append("\u2713 No issues found")

        if self.inferred_properties:
            lines.append("")

            lines.append("Inferred Properties:")

            for prop in self.inferred_properties:
                status = "\u2713" if prop.proof and prop.proof.status == ProofStatus.PROVEN else "?"

                lines.append(f"  {status} {prop.description}")

        return "\n".join(lines)
