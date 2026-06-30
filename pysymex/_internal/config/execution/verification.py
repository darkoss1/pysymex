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

"""Contract-aware verified execution configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict

from pysymex._internal.config.defaults import (
    DEFAULT_DETECT_OVERFLOW,
    DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS,
)
from pysymex._internal.execution.strategies.manager.types import ExplorationStrategy


@dataclass
class ExecutionVerificationConfig:
    """Configuration for verified symbolic execution."""

    max_paths: int | None = None
    max_depth: int | None = None
    max_iterations: int | None = None
    timeout_seconds: float | None = None
    strategy: ExplorationStrategy = ExplorationStrategy.ADAPTIVE
    max_loop_iterations: int | None = None
    solver_timeout_ms: int = DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS
    check_preconditions: bool = True
    check_postconditions: bool = True
    check_loop_invariants: bool = True
    check_class_invariants: bool = True
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


class ExecutionVerificationOverrides(TypedDict, total=False):
    """Typed keyword overrides accepted by ``verify``."""

    max_paths: int | None
    max_depth: int | None
    max_iterations: int | None
    timeout_seconds: float | None
    strategy: ExplorationStrategy
    max_loop_iterations: int | None
    solver_timeout_ms: int
    check_preconditions: bool
    check_postconditions: bool
    check_loop_invariants: bool
    check_class_invariants: bool
    infer_properties: bool
    detect_division_by_zero: bool
    detect_assertion_errors: bool
    detect_index_errors: bool
    detect_type_errors: bool
    detect_overflow: bool
    verbose: bool
    collect_coverage: bool
