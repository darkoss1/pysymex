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

"""Core symbolic execution run for verified executor workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.contracts.runtime.capture import (
    RuntimeContractOutcome,
    capture_runtime_contract_outcomes,
)
from pysymex._internal.execution.executors.verified.executor.settings import (
    execution_config_for_verified,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.analysis.detectors.detector.registry import DetectorRegistry
    from pysymex._internal.config.execution.verification import ExecutionVerificationConfig
    from pysymex._internal.execution.results.result import ExecutionResult

@dataclass(frozen=True, slots=True)
class SymbolicExecutionOutcome:
    """Core symbolic-execution result plus captured runtime contract outcomes."""

    core_result: ExecutionResult
    runtime_contract_outcomes: list[RuntimeContractOutcome]


def run_core_symbolic_execution(
    *,
    config: ExecutionVerificationConfig,
    detector_registry: DetectorRegistry,
    func: Callable[..., object],
    symbolic_args: dict[str, str],
) -> SymbolicExecutionOutcome:
    """Run the inner ``SymbolicExecutor`` and capture runtime contract outcomes."""
    from pysymex._internal.execution.executors.core import SymbolicExecutor

    core_executor = SymbolicExecutor(
        execution_config_for_verified(config),
        detector_registry,
    )
    with capture_runtime_contract_outcomes() as runtime_contract_outcomes:
        core_result = core_executor.execute_function(func, symbolic_args)
    return SymbolicExecutionOutcome(
        core_result=core_result,
        runtime_contract_outcomes=runtime_contract_outcomes,
    )
