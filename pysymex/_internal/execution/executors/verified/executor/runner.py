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

"""Verified executor runner and final result assembly."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.defaults import default_registry
from pysymex._internal.config.execution.verification import ExecutionVerificationConfig
from pysymex._internal.execution.executors.verified.executor.contracts import (
    collect_verified_contract_plan,
)
from pysymex._internal.execution.executors.verified.executor.core import run_core_symbolic_execution
from pysymex._internal.execution.executors.verified.executor.projection.core import (
    VerifiedCoreProjection,
    project_core_execution_result,
)
from pysymex._internal.execution.executors.verified.properties.types import (
    ProofStatus,
    PropertyKind,
    PropertyProof,
    PropertySpec,
)
from pysymex._internal.execution.executors.verified.types import (
    InferredProperty,
    VerifiedExecutionResult,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.analysis.detectors.detector.registry import DetectorRegistry


class VerifiedExecutor:
    """Symbolic executor with integrated contract and property verification.

    Owns contract checks around the core ``SymbolicExecutor``. Runtime
    contract evidence is captured from VM hooks and then projected into
    verified-execution reports.

    Supported contract kinds:
    - ``@requires`` preconditions (checked via solver on forked pre-states).
    - ``@ensures`` postconditions (checked via solver after symbolic execution).
    - Class invariants attached to ``__invariants__`` on constructors and
      public methods.
    - Frame-condition / ``@assigns`` checking for modeled writes.
    - Pure-effect (``@pure``) checking for modeled writes.

    Unsupported (reported as ``UNSUPPORTED``):
    - Loop invariant enforcement.
    """

    def __init__(
        self,
        config: ExecutionVerificationConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> None:
        """Store verified execution configuration and detector registry.

        Args:
            config: Verified execution limits and obligation toggles.
            detector_registry: Detector registry passed to inner ``SymbolicExecutor`` runs.

        """
        self.config = config or ExecutionVerificationConfig()
        self.detector_registry = detector_registry or default_registry

    def execute_function(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
    ) -> VerifiedExecutionResult:
        """Run symbolic execution with full contract and property verification.

        Constructs a fresh ``SymbolicExecutor`` using settings derived from
        ``config``, executes ``func``, then evaluates:

        - Declared ``@requires`` / ``@ensures`` contracts via Z3.
        - Class invariant obligations captured from runtime entry/exit hooks.
        - Arithmetic issue projection from core detector results.
        - Runtime contract outcomes captured from any ``capture_runtime_contract_outcomes``
          wrapper if the function has one.
        - Loop invariants are reported with ``VerificationResult.UNSUPPORTED``
          until loop-bound obligation hooks exist.

        Returns:
            A ``VerifiedExecutionResult`` with symbolic issues, contract
            results, property results, arithmetic issues, inferred properties,
            and termination status.

        """
        func_name = getattr(func, "__name__", "<lambda>")
        source_file = inspect.getsourcefile(func) or ""
        symbolic_args = symbolic_args or {}
        contract_plan = collect_verified_contract_plan(func, self.config)
        unwrapped_func = inspect.unwrap(func)

        core_outcome = run_core_symbolic_execution(
            config=self.config,
            detector_registry=self.detector_registry,
            func=unwrapped_func,
            symbolic_args=symbolic_args,
        )
        projection = project_core_execution_result(
            core_result=core_outcome.core_result,
            runtime_contract_outcomes=core_outcome.runtime_contract_outcomes,
            unwrapped_func=unwrapped_func,
            contract_plan=contract_plan,
        )

        inferred_properties = (
            infer_properties_from_projection(projection) if self.config.infer_properties else []
        )

        return VerifiedExecutionResult(
            issues=projection.issues,
            paths_explored=projection.paths_explored,
            paths_completed=projection.paths_completed,
            paths_pruned=projection.paths_pruned,
            coverage=projection.coverage,
            total_time_seconds=projection.total_time_seconds,
            function_name=func_name,
            source_file=source_file,
            contract_issues=projection.contract_issues,
            contract_evidence=projection.contract_evidence,
            contracts_checked=projection.contracts_checked,
            contracts_verified=projection.contracts_verified,
            contracts_violated=projection.contracts_violated,
            arithmetic_issues=projection.arithmetic_issues,
            inferred_properties=inferred_properties,
            termination_proof=None,
            degraded_passes=projection.degraded_passes,
        )


def infer_properties_from_projection(
    projection: VerifiedCoreProjection,
) -> list[InferredProperty]:
    """Infer conservative properties from verified execution projection evidence."""
    spec = PropertySpec(
        kind=PropertyKind.BOUNDED,
        name="bounded_execution_completion",
        description="Bounded symbolic execution completed all accounted paths without degradation.",
    )
    status = _bounded_execution_proof_status(projection)
    proof = PropertyProof(property=spec, status=status)
    confidence = 1.0 if status is ProofStatus.PROVEN else 0.0
    return [
        InferredProperty(
            kind=PropertyKind.BOUNDED,
            description=spec.description,
            confidence=confidence,
            proof=proof,
        ),
    ]


def _bounded_execution_proof_status(projection: VerifiedCoreProjection) -> ProofStatus:
    """Return whether projected execution evidence proves bounded completion."""
    if projection.degraded_passes:
        return ProofStatus.UNKNOWN
    if projection.paths_explored <= 0 or projection.paths_completed <= 0:
        return ProofStatus.UNKNOWN
    if projection.paths_completed + projection.paths_pruned < projection.paths_explored:
        return ProofStatus.UNKNOWN
    return ProofStatus.PROVEN
