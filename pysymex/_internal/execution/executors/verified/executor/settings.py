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

"""Core executor settings derived from verified execution settings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.config.execution.settings import ExecutionConfig

if TYPE_CHECKING:
    from pysymex._internal.config.execution.verification import ExecutionVerificationConfig


def execution_config_for_verified(config: ExecutionVerificationConfig) -> ExecutionConfig:
    """Build the inner symbolic-execution config for a verified execution run."""
    return ExecutionConfig(
        max_paths=config.max_paths,
        max_depth=config.max_depth,
        max_iterations=config.max_iterations,
        timeout_seconds=config.timeout_seconds,
        strategy=config.strategy,
        max_loop_iterations=config.max_loop_iterations,
        solver_timeout_ms=config.solver_timeout_ms,
        detect_division_by_zero=config.detect_division_by_zero,
        detect_assertion_errors=config.detect_assertion_errors,
        detect_index_errors=config.detect_index_errors,
        detect_type_errors=config.detect_type_errors,
        detect_overflow=config.bounded_overflow_enabled,
        verbose=config.verbose,
        collect_coverage=config.collect_coverage,
        use_loop_analysis=True,
        enable_contract_verification=(
            config.check_preconditions
            or config.check_postconditions
            or config.check_class_invariants
        ),
        check_contract_preconditions=config.check_preconditions,
        check_contract_postconditions=config.check_postconditions,
        check_contract_class_invariants=config.check_class_invariants,
    )
