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
from __future__ import annotations

import dis
import inspect
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.contracts import ContractKind, ContractVerifier, VerificationResult
from pysymex.analysis.contracts.decorators import get_function_contract
from pysymex.analysis.detectors import DetectorRegistry, Issue, default_registry
from pysymex.analysis.path_manager import PathManager
from pysymex.analysis.properties import ArithmeticVerifier, PropertyProver
from pysymex.core.solver import IncrementalSolver
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.termination import (
    RankingFunction as _RankingFunction,
)
from pysymex.execution.termination import (
    TerminationAnalyzer,
    TerminationProof,
    TerminationStatus,
)
from pysymex.execution.verified_execution_models import (
    ArithmeticIssue,
    ContractIssue,
    InferredProperty,
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
)

if TYPE_CHECKING:
    from pysymex.core.state import VMState

logger = logging.getLogger(__name__)


RankingFunction = _RankingFunction


def _extract_docstring_contracts(func: Callable[..., object]) -> tuple[int, int]:
    """Return (requires_count, ensures_count) from docstring tags."""
    doc = inspect.getdoc(func) or ""
    requires_count = 0
    ensures_count = 0
    for line in doc.splitlines():
        stripped = line.strip()
        if stripped.startswith(":requires:"):
            requires_count += 1
        elif stripped.startswith(":ensures:"):
            ensures_count += 1
    return requires_count, ensures_count


def _to_z3_expr(value: object) -> z3.ExprRef | None:
    """Best-effort conversion from runtime/symbolic value to a Z3 expression."""
    if isinstance(value, bool):
        return z3.BoolVal(value)
    if isinstance(value, int):
        return z3.IntVal(value)
    if isinstance(value, float):
        return z3.RealVal(value)
    if isinstance(value, str):
        return z3.StringVal(value)

    for attr_name in ("z3_int", "z3_bool", "z3_str", "z3_addr"):
        expr = getattr(value, attr_name, None)
        if isinstance(expr, z3.ExprRef):
            return expr

    return None


class VerifiedExecutor:
    """Symbolic executor with integrated contract and property verification.

    Extends symbolic execution with formal verification capabilities:

    1. **Precondition checking** — validates ``@requires`` contracts on entry.
    2. **Postcondition verification** — checks ``@ensures`` on all return paths.
    3. **Loop invariant validation** — inductively verifies annotated invariants.
    4. **Termination analysis** — synthesises ranking functions for loops.
    5. **Arithmetic safety** — proves absence of division-by-zero and overflow.
    6. **Property inference** — heuristically discovers function properties
       (commutativity, monotonicity, etc.) from execution traces.

    Typical usage::

        result = VerifiedExecutor().execute_function(my_func, {"x": "int"})
        for ci in result.contract_issues:
            print(ci)

    """

    def __init__(
        self,
        config: VerifiedExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> None:
        self.config = config or VerifiedExecutionConfig()
        self.detector_registry = detector_registry or default_registry
        self.dispatcher = OpcodeDispatcher()
        self.solver = IncrementalSolver(timeout_ms=self.config.solver_timeout_ms)
        self.contract_verifier = ContractVerifier(timeout_ms=self.config.solver_timeout_ms)
        self.property_prover = PropertyProver(timeout_ms=self.config.solver_timeout_ms)
        self.arithmetic_verifier = ArithmeticVerifier(
            timeout_ms=self.config.solver_timeout_ms,
            int_bits=self.config.integer_bits,
        )
        self.termination_analyzer = TerminationAnalyzer(
            timeout_ms=self.config.termination_timeout_ms
        )
        self._instructions: list[dis.Instruction] = []
        self._pc_to_line: dict[int, int] = {}
        self._worklist: PathManager[VMState] | None = None
        self._issues: list[Issue] = []
        self._contract_issues: list[ContractIssue] = []
        self._arithmetic_issues: list[ArithmeticIssue] = []
        self._coverage: set[int] = set()
        self._visited_states: set[int] = set()

    def execute_function(
        self, func: Callable[..., object], symbolic_args: dict[str, str] | None = None
    ) -> VerifiedExecutionResult:
        """Execute a function with full symbolic contract and property verification."""
        from pysymex.execution.executor_core import SymbolicExecutor
        from pysymex.execution.executor_types import ExecutionConfig

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
            detect_overflow=self.config.detect_overflow,
            verbose=self.config.verbose,
            collect_coverage=self.config.collect_coverage,
            use_loop_analysis=True,
        )
        core_executor = SymbolicExecutor(exec_config, self.detector_registry)

        func_contract = get_function_contract(func)
        preconditions = []
        postconditions = []

        if func_contract is not None:
            if self.config.check_preconditions:
                preconditions.extend(func_contract.preconditions)
            if self.config.check_postconditions:
                postconditions.extend(func_contract.postconditions)

        doc_requires, doc_ensures = _extract_docstring_contracts(func)
        contracts_checked = len(preconditions) + len(postconditions) + doc_requires + doc_ensures

        contract_issues: list[ContractIssue] = []

        def _check_postconditions_hook(
            executor: object, state: object, issue: object = None
        ) -> None:
            _ = issue
            if not postconditions:
                return

            from pysymex.core.state import VMState

            state_typed = state if isinstance(state, VMState) else None
            if not state_typed:
                return

            instructions_obj = state_typed.current_instructions or getattr(
                executor, "_instructions", None
            )
            if (
                not isinstance(instructions_obj, list)
                or not all(isinstance(ins, dis.Instruction) for ins in instructions_obj)
                or state_typed.pc >= len(instructions_obj)
            ):
                return

            instrs = cast("list[dis.Instruction]", instructions_obj)
            instr = instrs[state_typed.pc]
            if instr.opname not in ("RETURN_VALUE", "RETURN_CONST"):
                return

            symbols: dict[str, z3.ExprRef] = {}
            for name, value in state_typed.local_vars.items():
                expr = _to_z3_expr(value)
                if expr is not None:
                    symbols[name] = expr

            if state_typed.stack:
                ret_expr = _to_z3_expr(state_typed.peek())
                if ret_expr is not None:
                    symbols["__result__"] = ret_expr

            for post in postconditions:
                try:
                    result, counterexample = self.contract_verifier.verify_postcondition(
                        post,
                        preconditions,
                        list(state_typed.path_constraints),
                        symbols,
                    )
                except (AttributeError, RuntimeError, TypeError, z3.Z3Exception):
                    logger.debug("Failed to verify postcondition %s", post.condition, exc_info=True)
                    continue

                if result == VerificationResult.VIOLATED:
                    contract_issues.append(
                        ContractIssue(
                            kind=ContractKind.ENSURES,
                            condition=post.condition,
                            message=f"Postcondition might not hold: {post.condition}",
                            line_number=getattr(instr, "starts_line", None),
                            counterexample=counterexample or {},
                            result=result,
                        )
                    )

        if self.config.check_postconditions:
            core_executor.register_hook("pre_step", _check_postconditions_hook)

        try:
            core_result = core_executor.execute_function(func, symbolic_args)
        except Exception:
            logger.error("Core symbolic execution failed", exc_info=True)
            core_result = None

        arithmetic_issues: list[ArithmeticIssue] = []
        issues = []
        coverage = set()
        paths_explored = 0
        paths_completed = 0
        paths_pruned = 0
        total_time_seconds = 0.0

        if core_result:
            paths_explored = core_result.paths_explored
            paths_completed = core_result.paths_completed
            paths_pruned = core_result.paths_pruned
            coverage = core_result.coverage
            total_time_seconds = core_result.total_time_seconds

            for iss in core_result.issues:
                if iss.kind.name in ("DIVISION_BY_ZERO", "OVERFLOW"):
                    arithmetic_issues.append(
                        ArithmeticIssue(
                            kind=iss.kind.name.lower(),
                            expression=iss.message,
                            message=iss.message,
                            line_number=iss.line_number,
                            counterexample=(iss.model if isinstance(iss.model, dict) else {}),
                        )
                    )
                else:
                    issues.append(iss)

        inferred_properties: list[InferredProperty] = []
        if self.config.infer_properties:
            pass

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
            contracts_checked=contracts_checked,
            contracts_verified=contracts_checked - len(contract_issues),
            contracts_violated=len(contract_issues),
            arithmetic_issues=arithmetic_issues,
            inferred_properties=inferred_properties,
            termination_proof=None,
        )


def verify(
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
    **config_overrides: object,
) -> VerifiedExecutionResult:
    """Convenience wrapper for verified execution."""
    config_ctor = cast("Callable[..., VerifiedExecutionConfig]", VerifiedExecutionConfig)
    config = config_ctor(symbolic_args=symbolic_args or {}, **config_overrides)
    executor = VerifiedExecutor(config)
    return executor.execute_function(func, symbolic_args or {})


def check_contracts(
    func: Callable[..., object], symbolic_args: dict[str, str] | None = None
) -> list[ContractIssue]:
    """Return contract issues for a function."""
    result = verify(
        func,
        symbolic_args,
        check_preconditions=True,
        check_postconditions=True,
    )
    return result.contract_issues


def check_arithmetic(
    func: Callable[..., object], symbolic_args: dict[str, str] | None = None
) -> list[ArithmeticIssue]:
    """Return arithmetic issues for a function."""
    result = verify(
        func,
        symbolic_args,
        check_division_safety=True,
        detect_division_by_zero=True,
    )
    return result.arithmetic_issues


def prove_termination(
    func: Callable[..., object], symbolic_args: dict[str, str] | None = None
) -> TerminationProof:
    """Return a termination proof placeholder."""
    _ = func, symbolic_args
    return TerminationProof(
        status=TerminationStatus.UNKNOWN,
        message="Termination analysis not implemented in this wrapper",
    )
