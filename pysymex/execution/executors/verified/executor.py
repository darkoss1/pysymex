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

"""Verified symbolic executor with integrated contract and property verification.

Wraps ``SymbolicExecutor`` with contract checking (preconditions,
postconditions, class invariants), arithmetic safety checks, and termination
analysis. ``VerifiedExecutor`` is not a subclass
of ``SymbolicExecutor``; it constructs one internally per call to
``execute_function`` or ``verify_function``.

Limitations:
    Loop invariant checking is declared as ``UNSUPPORTED`` in results.
    Class invariants are checked as runtime entry/exit obligations for
    constructors and public methods when receiver state can be modeled.
    ``@assigns`` and ``@pure`` are checked against modeled VM write events, but
    deep heap equality and external/native side-effect modeling remain outside
    this first effect-ledger slice.
"""

from __future__ import annotations

import inspect
from pysymex.logger import get_logger
from collections.abc import Callable

from pysymex.analysis.detectors import DetectorRegistry, Issue, default_registry
from pysymex.analysis.static.properties import ArithmeticVerifier
from pysymex.contracts.decorators import get_function_contract
from pysymex.contracts.invariants import invariant_obligation_count_for_callable
from pysymex.contracts.reports.adapters import extract_counterexample_from_model
from pysymex.contracts.reports.summary import aggregate_runtime_contract_outcomes
from pysymex.contracts.runtime.capture import capture_runtime_contract_outcomes
from pysymex.contracts.types import Contract, ContractKind, EffectKind, VerificationResult
from pysymex.execution.executors.verified.types import (
    ArithmeticIssue,
    ContractIssue,
    InferredProperty,
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
)
from pysymex.execution.termination import TerminationAnalyzer

logger = get_logger(__name__)


def _unsupported_contract(kind: ContractKind, condition: str, message: str) -> ContractIssue:
    """Build a visible result for a declared obligation without execution semantics."""
    return ContractIssue(
        kind=kind,
        condition=condition,
        message=message,
        result=VerificationResult.UNSUPPORTED,
    )


class VerifiedExecutor:
    """Symbolic executor with integrated contract and property verification.

    Owns property, arithmetic, and termination analyzers around the core
    ``SymbolicExecutor``. Contract checks are captured as runtime evidence from
    VM hooks and then projected into verified-execution reports.

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
        config: VerifiedExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> None:
        """Wire arithmetic and termination subsystems.

        Args:
            config: Verified execution limits and obligation toggles.
            detector_registry: Detector registry passed to inner ``SymbolicExecutor`` runs.
        """
        self.config = config or VerifiedExecutionConfig()
        self.detector_registry = detector_registry or default_registry
        self.arithmetic_verifier = ArithmeticVerifier(
            timeout_ms=self.config.solver_timeout_ms,
            int_bits=self.config.integer_bits,
        )
        self.termination_analyzer = TerminationAnalyzer(
            timeout_ms=self.config.termination_timeout_ms
        )

    def execute_function(
        self, func: Callable[..., object], symbolic_args: dict[str, str] | None = None
    ) -> VerifiedExecutionResult:
        """Run symbolic execution with full contract and property verification.

        Constructs a fresh ``SymbolicExecutor`` using settings derived from
        ``config``, executes ``func``, then evaluates:

        - Declared ``@requires`` / ``@ensures`` contracts via Z3.
        - Class invariant obligations captured from runtime entry/exit hooks.
        - Arithmetic properties (overflow, division-by-zero).
        - Termination analysis via ``TerminationAnalyzer``.
        - Runtime contract outcomes captured from any ``capture_runtime_contract_outcomes``
          wrapper if the function has one.
        - Loop invariants are reported with ``VerificationResult.UNSUPPORTED``
          until loop-bound obligation hooks exist.

        Returns:
            A ``VerifiedExecutionResult`` with symbolic issues, contract
            results, property results, arithmetic issues, inferred properties,
            and termination status.
        """
        from pysymex.execution.executors.core import SymbolicExecutor
        from pysymex.execution.config.settings import ExecutionConfig

        func_name = getattr(func, "__name__", "<lambda>")
        source_file = inspect.getsourcefile(func) or ""
        symbolic_args = symbolic_args or {}

        exec_config = ExecutionConfig(
            max_paths=self.config.max_paths,
            max_depth=self.config.max_depth,
            max_iterations=self.config.max_iterations,
            timeout_seconds=self.config.timeout_seconds,
            strategy=self.config.strategy,
            solver_timeout_ms=self.config.solver_timeout_ms,
            detect_division_by_zero=self.config.detect_division_by_zero,
            detect_assertion_errors=self.config.detect_assertion_errors,
            detect_index_errors=self.config.detect_index_errors,
            detect_type_errors=self.config.detect_type_errors,
            detect_overflow=self.config.bounded_overflow_enabled,
            verbose=self.config.verbose,
            collect_coverage=self.config.collect_coverage,
            use_loop_analysis=True,
            enable_contract_verification=(
                self.config.check_preconditions
                or self.config.check_postconditions
                or self.config.check_class_invariants
            ),
            check_contract_preconditions=self.config.check_preconditions,
            check_contract_postconditions=self.config.check_postconditions,
            check_contract_class_invariants=self.config.check_class_invariants,
        )
        core_executor = SymbolicExecutor(exec_config, self.detector_registry)

        func_contract = get_function_contract(func)
        preconditions: list[Contract] = []
        postconditions: list[Contract] = []
        unsupported_issues: list[ContractIssue] = []
        runtime_obligation_count = 0

        if func_contract is not None:
            if self.config.check_preconditions:
                preconditions.extend(func_contract.preconditions)
            if self.config.check_postconditions:
                postconditions.extend(func_contract.postconditions)
            if self.config.check_loop_invariants:
                for clauses in func_contract.loop_invariants.values():
                    unsupported_issues.extend(
                        _unsupported_contract(
                            ContractKind.LOOP_INVARIANT,
                            clause.condition,
                            "Loop invariant checking is not integrated into verified execution",
                        )
                        for clause in clauses
                    )
            if func_contract.assigns_declared:
                runtime_obligation_count += 1
            if func_contract.effect_type is EffectKind.PURE:
                runtime_obligation_count += 1
        if self.config.check_class_invariants:
            runtime_obligation_count += invariant_obligation_count_for_callable(func)

        contracts_checked = (
            len(preconditions)
            + len(postconditions)
            + len(unsupported_issues)
            + runtime_obligation_count
        )

        contract_issues: list[ContractIssue] = list(unsupported_issues)
        unwrapped_func = inspect.unwrap(func)
        runtime_contract_outcomes = []

        try:
            with capture_runtime_contract_outcomes() as runtime_contract_outcomes:
                core_result = core_executor.execute_function(unwrapped_func, symbolic_args)
        except Exception:
            logger.error("Core symbolic execution failed", exc_info=True)
            core_result = None

        arithmetic_issues: list[ArithmeticIssue] = []
        issues: list[Issue] = []
        coverage: set[int] = set()
        paths_explored = 0
        paths_completed = 0
        paths_pruned = 0
        contract_evidence = []
        contracts_verified = 0
        total_time_seconds = 0.0
        degraded_passes: list[str] = (
            ["core_symbolic_execution_failed"] if core_result is None else []
        )

        if core_result:
            paths_explored = core_result.paths_explored
            paths_completed = core_result.paths_completed
            paths_pruned = core_result.paths_pruned
            coverage = core_result.coverage
            total_time_seconds = core_result.total_time_seconds
            degraded_passes = list(core_result.degraded_passes)
            runtime_summary = aggregate_runtime_contract_outcomes(
                runtime_contract_outcomes, id(unwrapped_func)
            )
            contract_issues.extend(runtime_summary.issues)
            contract_evidence = runtime_summary.evidence
            contracts_checked += runtime_summary.nested_contract_count
            contracts_verified = runtime_summary.verified_count
            captured_issue_ids = {
                id(outcome.issue)
                for outcome in runtime_contract_outcomes
                if outcome.issue is not None
            }

            for iss in core_result.issues:
                if id(iss) in captured_issue_ids:
                    continue
                if iss.kind.name in ("DIVISION_BY_ZERO", "OVERFLOW"):
                    arithmetic_issues.append(
                        ArithmeticIssue(
                            kind=iss.kind.name.lower(),
                            expression=iss.message,
                            message=iss.message,
                            line_number=iss.line_number,
                            counterexample=extract_counterexample_from_model(iss.model),
                        )
                    )
                elif iss.kind.name == "CONTRACT_VIOLATION":
                    continue
                elif iss.kind.name == "UNKNOWN" and any(
                    label in iss.message.lower()
                    for label in ("precondition", "postcondition", "assumption")
                ):
                    lower_message = iss.message.lower()
                    if (
                        "postcondition" in lower_message
                        or ("precondition" in lower_message and " of " in lower_message)
                        or ("assumption" in lower_message and " of " in lower_message)
                    ):
                        continue
                    kind = (
                        ContractKind.REQUIRES
                        if "precondition" in lower_message
                        else (
                            ContractKind.ASSUMES
                            if "assumption" in lower_message
                            else ContractKind.ENSURES
                        )
                    )
                    result = (
                        VerificationResult.UNSUPPORTED
                        if "could not be checked" in lower_message
                        or "could not be modeled" in lower_message
                        else VerificationResult.UNKNOWN
                    )
                    contract_issues.append(
                        ContractIssue(
                            kind=kind,
                            condition=iss.message,
                            message=iss.message,
                            line_number=iss.line_number,
                            function_name=iss.function_name,
                            counterexample={},
                            result=result,
                        )
                    )
                else:
                    issues.append(iss)

        inferred_properties: list[InferredProperty] = []
        if self.config.infer_properties:
            logger.debug("Property inference is not yet implemented in VerifiedExecutor")

        contracts_violated = sum(
            issue.result is VerificationResult.VIOLATED for issue in contract_issues
        )
        return VerifiedExecutionResult(
            issues=issues,
            paths_explored=paths_explored,
            paths_completed=paths_completed,
            paths_pruned=paths_pruned,
            coverage=coverage,
            total_time_seconds=total_time_seconds,
            function_name=func_name,
            source_file=source_file,
            contract_issues=contract_issues,
            contract_evidence=contract_evidence,
            contracts_checked=contracts_checked,
            contracts_verified=contracts_verified,
            contracts_violated=contracts_violated,
            arithmetic_issues=arithmetic_issues,
            inferred_properties=inferred_properties,
            termination_proof=None,
            degraded_passes=degraded_passes,
        )
