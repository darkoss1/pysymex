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

"""Execution input policy and run-option data."""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.execution.frontier import FrontierRuntimeMode
from pysymex.execution.strategies.manager.types import ExplorationStrategy

__all__ = ["ExecutionConfig", "FrontierRuntimeMode"]


@dataclass(frozen=True, slots=True)
class ExecutionConfig:
    """Configuration values consumed by symbolic execution components.

    The dataclass prevents rebinding its fields after construction, but
    ``symbolic_args`` remains a mutable referenced dictionary.
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
    enable_caching: bool = True
    use_type_hints: bool = True
    enable_state_merging: bool = True
    merge_policy: str = "moderate"
    enable_fp_filtering: bool = True
    enable_cross_function: bool = True
    enable_type_inference: bool = True
    symbolic_args: dict[str, str] = field(default_factory=dict[str, str])
    lazy_eval_threshold: int = 20
    enable_concurrency_analysis: bool = False
    enable_contract_verification: bool = False
    check_contract_preconditions: bool = True
    check_contract_postconditions: bool = True
    check_contract_class_invariants: bool = True
    max_interleavings: int = 1000
    dpor_enabled: bool = True
    enable_solver_cache: bool = True
    heuristic_assume_non_null_self: bool = True
    deterministic_mode: bool = True
    random_seed: int = 42
    frontier_runtime_mode: FrontierRuntimeMode = FrontierRuntimeMode.POLAR_CEGIS_RUNTIME
