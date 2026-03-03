"""Executor types — configuration, result dataclass, and constants."""

from __future__ import annotations


from dataclasses import dataclass, field

from typing import Any


from pysymex.analysis.detectors import Issue, IssueKind

from pysymex.analysis.path_manager import ExplorationStrategy

__all__ = [
    "ExecutionConfig",
    "ExecutionResult",
    "BRANCH_OPCODES",
]


BRANCH_OPCODES: frozenset[str] = frozenset(
    {
        "POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_FORWARD_IF_TRUE",
        "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_FORWARD_IF_NONE",
        "POP_JUMP_FORWARD_IF_NOT_NONE",
        "POP_JUMP_BACKWARD_IF_TRUE",
        "POP_JUMP_BACKWARD_IF_FALSE",
        "POP_JUMP_BACKWARD_IF_NONE",
        "POP_JUMP_BACKWARD_IF_NOT_NONE",
        "JUMP_IF_TRUE_OR_POP",
        "JUMP_IF_FALSE_OR_POP",
        "FOR_ITER",
        "SEND",
    }
)


@dataclass(slots=True)
class ExecutionConfig:
    """Configuration for symbolic execution."""

    max_paths: int = 10000

    max_depth: int = 1000

    max_iterations: int = 100000

    timeout_seconds: float = 300.0

    strategy: ExplorationStrategy = ExplorationStrategy.DFS

    max_loop_iterations: int = 100

    unroll_loops: bool = True

    solver_timeout_ms: int = 10000

    use_incremental_solving: bool = True

    detect_division_by_zero: bool = True

    detect_assertion_errors: bool = True

    detect_index_errors: bool = True

    detect_type_errors: bool = True

    detect_overflow: bool = False

    detect_value_errors: bool = True

    verbose: bool = False

    collect_coverage: bool = True

    use_loop_analysis: bool = False

    enable_taint_tracking: bool = True

    enable_caching: bool = True

    use_type_hints: bool = True

    enable_state_merging: bool = True

    merge_policy: str = "moderate"

    enable_fp_filtering: bool = True

    enable_cross_function: bool = True

    enable_type_inference: bool = True

    enable_abstract_interpretation: bool = True

    symbolic_args: dict[str, str] = field(default_factory=dict[str, str])

    lazy_eval_threshold: int = 20

    enable_concurrency_analysis: bool = False

    max_interleavings: int = 1000

    dpor_enabled: bool = True


@dataclass(slots=True)
class ExecutionResult:
    """Result of symbolic execution."""

    issues: list[Issue] = field(default_factory=list[Issue])

    paths_explored: int = 0

    paths_completed: int = 0

    paths_pruned: int = 0

    coverage: set[int] = field(default_factory=set[int])

    total_time_seconds: float = 0.0

    solver_time_seconds: float = 0.0

    function_name: str = ""

    source_file: str = ""

    final_globals: dict[str, Any] = field(default_factory=dict[str, Any])

    final_locals: dict[str, Any] = field(default_factory=dict[str, Any])

    def has_issues(self) -> bool:
        """Check if any issues were found."""

        return len(self.issues) > 0

    def get_issues_by_kind(self, kind: IssueKind) -> list[Issue]:
        """Get issues of a specific kind."""

        return [i for i in self.issues if i.kind == kind]

    def format_summary(self) -> str:
        """Format a summary of results."""

        lines = [
            "=== PySyMex Execution Results ===",
            f"Function: {self.function_name}",
            f"Paths explored: {self.paths_explored}",
            f"Paths completed: {self.paths_completed}",
            f"Coverage: {len(self.coverage)} bytecode instructions",
            f"Total time: {self.total_time_seconds:.2f}s",
            "",
        ]

        if self.issues:
            lines.append(f"Issues found: {len(self.issues)}")

            for issue in self.issues:
                lines.append("")

                lines.append(issue.format())

        else:
            lines.append("No issues found!")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""

        return {
            "function_name": self.function_name,
            "source_file": self.source_file,
            "paths_explored": self.paths_explored,
            "paths_completed": self.paths_completed,
            "paths_pruned": self.paths_pruned,
            "coverage_size": len(self.coverage),
            "total_time_seconds": self.total_time_seconds,
            "issues": [i.to_dict() for i in self.issues],
        }

    def to_sarif(self, output_path: str | None = None) -> dict[str, Any]:
        """Convert to SARIF v2.1.0 format for IDE/CI integration.

        Uses the existing SARIFGenerator from pysymex.reporting.sarif.

        Args:
            output_path: If provided, write the SARIF JSON to this file.

        Returns:
            SARIF log as a dictionary.
        """

        from pysymex.reporting.sarif import SARIFGenerator

        generator = SARIFGenerator(
            tool_name="pysymex",
            tool_version="0.3.0-alpha",
        )

        issue_dicts: list[dict[str, Any]] = []

        for issue in self.issues:
            issue_dict: dict[str, Any] = {
                "type": issue.kind.name.lower(),
                "message": issue.message,
                "line": issue.line_number or 0,
                "file": issue.filename or self.source_file or "",
            }

            counterexample = issue.get_counterexample()

            if counterexample:
                issue_dict["triggering_input"] = counterexample

            issue_dicts.append(issue_dict)

        sarif_log = generator.generate(
            issues=issue_dicts,
            analyzed_files=[self.source_file] if self.source_file else [],
        )

        sarif_dict = sarif_log.to_dict()

        if sarif_dict.get("runs"):
            run = sarif_dict["runs"][0]

            if run.get("invocations"):
                run["invocations"][0]["properties"] = {
                    "pathsExplored": self.paths_explored,
                    "pathsCompleted": self.paths_completed,
                    "pathsPruned": self.paths_pruned,
                    "coverageInstructions": len(self.coverage),
                    "totalTimeSeconds": round(self.total_time_seconds, 3),
                }

        if output_path:
            import json

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(sarif_dict, f, indent=2, default=str)

        return sarif_dict
