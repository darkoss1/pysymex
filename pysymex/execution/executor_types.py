# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Executor types — configuration, result dataclass, and constants."""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.path_manager import ExplorationStrategy

__all__ = [
    "BRANCH_OPCODES",
    "ExecutionConfig",
    "ExecutionResult",
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


@dataclass(frozen=True, slots=True)
class ExecutionConfig:
    """Configuration for symbolic execution.

    Controls exploration bounds, solver parameters, detector toggles,
    and optional analysis passes.  Frozen so it can be shared safely
    across threads and cached without defensive copies.

    Attributes:
        max_paths: Maximum number of execution paths to explore.
        max_depth: Maximum call/recursion depth per path.
        max_iterations: Global iteration budget across all paths.
        timeout_seconds: Wall-clock timeout for the entire analysis.
        strategy: Path exploration strategy (CHTD-native, adaptive, coverage, etc.).
        max_loop_iterations: Per-loop iteration cap before widening/pruning.
        unroll_loops: Whether to unroll loops during exploration.
        solver_timeout_ms: Z3 solver timeout per query in milliseconds.
        use_incremental_solving: Use incremental Z3 solver for performance.
        detect_division_by_zero: Enable division-by-zero detector.
        detect_assertion_errors: Enable assertion-error detector.
        detect_index_errors: Enable index-out-of-bounds detector.
        detect_type_errors: Enable type-mismatch detector.
        detect_overflow: Enable integer-overflow detector.
        detect_value_errors: Enable value-error detector.
        verbose: Print verbose diagnostic output during analysis.
        collect_coverage: Track bytecode instruction coverage.
        use_loop_analysis: Enable CFG-based loop detection and widening.
        enable_taint_tracking: Enable taint-flow analysis.
        enable_caching: Cache execution results by function signature.
        use_type_hints: Extract type hints to refine symbolic types.
        enable_state_merging: Merge similar states at join points.
        merge_policy: State-merging aggressiveness (conservative/moderate/aggressive).
        enable_fp_filtering: Apply false-positive filtering to results.
        enable_cross_function: Run inter-procedural analysis.
        enable_type_inference: Run type-inference pre-pass.
        enable_abstract_interpretation: Run abstract-interpretation pre-pass.
        symbolic_args: Default symbolic argument type overrides.
        lazy_eval_threshold: Pending constraints before forcing a Z3 check.
        enable_concurrency_analysis: Enable threading/async race detection.
        max_interleavings: Max scheduling permutations for async analysis.
        dpor_enabled: Use Dynamic Partial Order Reduction for interleavings.
    """

    max_paths: int = 10000
    max_depth: int = 1000
    max_iterations: int = 100000
    timeout_seconds: float = 300.0
    strategy: ExplorationStrategy = ExplorationStrategy.ADAPTIVE
    max_loop_iterations: int = 10
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
    use_loop_analysis: bool = True
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
    enable_solver_cache: bool = True
    heuristic_assume_non_null_self: bool = True
    enable_interaction_graph: bool = True
    enable_chtd: bool = True
    enable_h_acceleration: bool = True
    # Default to deterministic scheduling so CI and API-level checks are reproducible.
    deterministic_mode: bool = True
    random_seed: int = 42
    chtd_max_branch_infos: int = 256
    chtd_check_interval: int = 64
    chtd_adaptive_interval: bool = True
    chtd_min_check_interval: int = 8
    chtd_max_check_interval: int = 128
    chtd_growth_trigger: int = 8


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Result of symbolic execution.

    Immutable summary produced by :class:`SymbolicExecutor` after
    exploring all feasible paths (or hitting resource limits).

    Attributes:
        issues: Detected bugs/warnings sorted by severity.
        paths_explored: Total execution paths explored.
        paths_completed: Paths that reached a ``RETURN`` opcode.
        paths_pruned: Paths pruned by infeasibility, dedup, or limits.
        coverage: Set of bytecode instruction offsets executed.
        total_time_seconds: Wall-clock time for the full analysis.
        solver_time_seconds: Cumulative Z3 solver time.
        function_name: Name of the analysed function.
        source_file: Source file path of the analysed function.
        final_globals: Global variable state at the last completed path.
        final_locals: Local variable state at the last completed path.
    """

    issues: list[Issue] = field(default_factory=list[Issue])
    paths_explored: int = 0
    paths_completed: int = 0
    paths_pruned: int = 0
    coverage: set[int] = field(default_factory=set[int])
    total_time_seconds: float = 0.0
    solver_time_seconds: float = 0.0
    function_name: str = ""
    source_file: str = ""
    final_globals: dict[str, object] = field(default_factory=dict[str, object])
    final_locals: dict[str, object] = field(default_factory=dict[str, object])
    branches: list[object] = field(default_factory=list[object])
    treewidth_stats: dict[str, object] = field(default_factory=dict[str, object])
    solver_stats: dict[str, object] = field(default_factory=dict[str, object])
    degraded_passes: list[str] = field(default_factory=list[str])

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

    def to_dict(self) -> dict[str, object]:
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

    def to_sarif(self, output_path: str | None = None) -> dict[str, object]:
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
        issue_dicts: list[dict[str, object]] = []
        for issue in self.issues:
            issue_dict: dict[str, object] = {
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

        runs_obj = sarif_dict.get("runs")
        if isinstance(runs_obj, list) and runs_obj:
            run = runs_obj[0]
            if isinstance(run, dict):
                invocations = run.get("invocations")
                if (
                    isinstance(invocations, list)
                    and invocations
                    and isinstance(invocations[0], dict)
                ):
                    invocations[0]["properties"] = {
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
