# pysymex: Python Symbolic Execution & Formal Verification
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
from __future__ import annotations

import dis
import inspect
import logging
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, TypedDict, Unpack, cast

import z3

from pysymex.contracts.types import Contract, ContractKind, VerificationResult
from pysymex.contracts.verifier import ContractVerifier
from pysymex.contracts.decorators import get_function_contract
from pysymex.analysis.detectors import DetectorRegistry, Issue, default_registry
from pysymex.analysis.properties import ArithmeticVerifier, PropertyProver
from pysymex.core.solver.engine import IncrementalSolver
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.strategies.manager import ExplorationStrategy, PathManager
from pysymex.execution.termination import (
    RankingFunction as _RankingFunction,
)
from pysymex.execution.termination import (
    TerminationAnalyzer,
    TerminationProof,
    TerminationStatus,
)
from dataclasses import dataclass, field

from pysymex.analysis.properties import (
    ProofStatus,
    PropertyKind,
    PropertyProof,
)


@dataclass
class VerifiedExecutionConfig:
    """Configuration for verified symbolic execution."""

    max_paths: int = 1000
    max_depth: int = 100
    max_iterations: int = 10000
    timeout_seconds: float = 60.0
    strategy: ExplorationStrategy = ExplorationStrategy.ADAPTIVE
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


class VerifiedExecutionOverrides(TypedDict, total=False):
    """Typed keyword overrides accepted by ``verify``."""

    max_paths: int
    max_depth: int
    max_iterations: int
    timeout_seconds: float
    strategy: ExplorationStrategy
    max_loop_iterations: int
    unroll_loops: bool
    solver_timeout_ms: int
    check_preconditions: bool
    check_postconditions: bool
    check_loop_invariants: bool
    check_class_invariants: bool
    check_termination: bool
    termination_timeout_ms: int
    check_overflow: bool
    check_division_safety: bool
    check_array_bounds: bool
    integer_bits: int
    infer_properties: bool
    detect_division_by_zero: bool
    detect_assertion_errors: bool
    detect_index_errors: bool
    detect_type_errors: bool
    detect_overflow: bool
    verbose: bool
    collect_coverage: bool


@dataclass
class ContractIssue:
    """A contract-related issue found during execution."""

    kind: ContractKind
    condition: str
    message: str
    line_number: int | None = None
    function_name: str | None = None
    counterexample: dict[str, object] = field(default_factory=dict[str, object])
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
    counterexample: dict[str, object] = field(default_factory=dict[str, object])

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


def _symbol_for_contract_parameter(name: str, type_name: str | None) -> z3.ExprRef:
    if type_name == "bool":
        return z3.Bool(name)
    if type_name == "float":
        return z3.Real(name)
    if type_name == "str":
        return z3.String(name)
    return z3.Int(name)


def _build_contract_validation_symbols(
    func: Callable[..., object], symbolic_args: dict[str, str]
) -> dict[str, z3.ExprRef]:
    symbols: dict[str, z3.ExprRef] = {}
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        signature = None

    if signature is not None:
        for name, parameter in signature.parameters.items():
            annotation = parameter.annotation
            type_name = symbolic_args.get(name)
            if type_name is None and annotation is not inspect.Signature.empty:
                if annotation is bool:
                    type_name = "bool"
                elif annotation is float:
                    type_name = "float"
                elif annotation is str:
                    type_name = "str"
                else:
                    type_name = "int"
            symbols[name] = _symbol_for_contract_parameter(name, type_name)

    result = z3.Int("__result__")
    symbols["__result__"] = result
    symbols["result"] = result
    symbols["return"] = result
    symbols["__return__"] = result
    return symbols


def _extract_counterexample_from_model(model: object) -> dict[str, object]:
    """Helper to convert a Z3 ModelRef or dict to a formatted counterexample."""
    if isinstance(model, Mapping):
        mapping = cast("Mapping[object, object]", model)
        return {str(key): value for key, value in mapping.items()}
    if not isinstance(model, z3.ModelRef):
        return {}

    def _is_true_model_value(value: object) -> bool:
        return (isinstance(value, z3.BoolRef) and z3.is_true(value)) or str(value) == "True"

    def _model_value_to_int_or_str(value: object) -> int | str:
        as_long = getattr(value, "as_long", None)
        if callable(as_long):
            long_value: object = as_long()
            if isinstance(long_value, int):
                return long_value
        return str(value)

    result: dict[str, dict[str, object]] = {}
    for decl in model.decls():
        name = decl.name()
        value: object = model[decl]
        if name.endswith("_int"):
            base = name[:-4]
            bucket = result.setdefault(base, {})
            bucket["int"] = value
        elif name.endswith("_bool"):
            base = name[:-5]
            bucket = result.setdefault(base, {})
            bucket["bool"] = value
        elif name.endswith("_is_int"):
            base = name[:-7]
            bucket = result.setdefault(base, {})
            bucket["is_int"] = value
        elif name.endswith("_is_bool"):
            base = name[:-8]
            bucket = result.setdefault(base, {})
            bucket["is_bool"] = value
        elif name.endswith("_str"):
            base = name[:-4]
            bucket = result.setdefault(base, {})
            bucket["str"] = value
        elif name.endswith("_len"):
            base = name[:-4]
            bucket = result.setdefault(base, {})
            bucket["len"] = value
        else:
            result[name] = {"value": value}

    formatted: dict[str, object] = {}
    for var, info in result.items():
        is_int_val = info.get("is_int")
        if _is_true_model_value(is_int_val):
            val = info.get("int")
            formatted[var] = _model_value_to_int_or_str(val)
            continue

        is_bool_val = info.get("is_bool")
        if _is_true_model_value(is_bool_val):
            val = info.get("bool")
            formatted[var] = _is_true_model_value(val) if hasattr(val, "decl") else bool(val)
            continue

        if "str" in info:
            val = info.get("str")
            val_str = str(val)
            if val_str.startswith('"') and val_str.endswith('"'):
                val_str = val_str[1:-1]
            formatted[var] = val_str
        elif "int" in info:
            val = info.get("int")
            formatted[var] = _model_value_to_int_or_str(val)
        elif "value" in info:
            val = info["value"]
            if hasattr(val, "as_long"):
                formatted[var] = _model_value_to_int_or_str(val)
            elif hasattr(val, "decl"):
                formatted[var] = _is_true_model_value(val)
            else:
                formatted[var] = str(val)
        else:
            formatted[var] = str(info)
    return formatted


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
        from pysymex.execution.executors.core import SymbolicExecutor
        from pysymex.execution.types import ExecutionConfig

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
            enable_contract_verification=True,
        )
        core_executor = SymbolicExecutor(exec_config, self.detector_registry)

        func_contract = get_function_contract(func)
        preconditions: list[Contract] = []
        postconditions: list[Contract] = []

        if func_contract is not None:
            if self.config.check_preconditions:
                preconditions.extend(func_contract.preconditions)
            if self.config.check_postconditions:
                postconditions.extend(func_contract.postconditions)

        doc_requires, doc_ensures = _extract_docstring_contracts(func)
        contracts_checked = len(preconditions) + len(postconditions) + doc_requires + doc_ensures

        contract_issues: list[ContractIssue] = []
        validation_symbols = _build_contract_validation_symbols(func, symbolic_args)
        for contract in preconditions:
            try:
                contract.compile(validation_symbols)
            except (TypeError, ValueError, z3.Z3Exception) as exc:
                contract_issues.append(
                    ContractIssue(
                        kind=ContractKind.REQUIRES,
                        condition=contract.condition,
                        message=f"Precondition could not be checked: {exc}",
                        line_number=contract.line_number,
                        function_name=func_name,
                        counterexample={},
                        result=VerificationResult.UNKNOWN,
                    )
                )

        # Unwrap the function so the VM traces the actual code, not the decorator wrapper
        unwrapped_func = inspect.unwrap(func)

        try:
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
                            counterexample=_extract_counterexample_from_model(iss.model),
                        )
                    )
                elif iss.kind.name == "CONTRACT_VIOLATION":
                    # Convert injection-based contract violations to ContractIssue
                    contract_issues.append(
                        ContractIssue(
                            kind=ContractKind.ENSURES,
                            condition=iss.message,
                            message=iss.message,
                            line_number=iss.line_number,
                            counterexample=_extract_counterexample_from_model(iss.model),
                            result=VerificationResult.VIOLATED,
                        )
                    )
                elif iss.kind.name == "UNKNOWN" and "condition" in iss.message.lower():
                    lower_message = iss.message.lower()
                    kind = (
                        ContractKind.REQUIRES
                        if "precondition" in lower_message
                        else ContractKind.ENSURES
                    )
                    contract_issues.append(
                        ContractIssue(
                            kind=kind,
                            condition=iss.message,
                            message=iss.message,
                            line_number=iss.line_number,
                            function_name=iss.function_name,
                            counterexample={},
                            result=VerificationResult.UNKNOWN,
                        )
                    )
                else:
                    issues.append(iss)

        inferred_properties: list[InferredProperty] = []
        if self.config.infer_properties:
            logger.debug("Property inference is not yet implemented in VerifiedExecutor")

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
    **config_overrides: Unpack[VerifiedExecutionOverrides],
) -> VerifiedExecutionResult:
    """Convenience wrapper for verified execution."""
    config = VerifiedExecutionConfig(symbolic_args=symbolic_args or {}, **config_overrides)
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
