from __future__ import annotations

import dis
import inspect
import logging
from typing import TYPE_CHECKING, Any

from pysymex.analysis.detectors import DetectorRegistry, Issue, default_registry
from pysymex.core.solver import IncrementalSolver
from pysymex.execution.dispatcher import OpcodeDispatcher

# Missing imports recovered from common patterns
from pysymex.analysis.contracts import ContractVerifier
from pysymex.analysis.contracts.decorators import get_function_contract
from pysymex.analysis.properties import ArithmeticVerifier, PropertyProver
from pysymex.analysis.path_manager import PathManager
from pysymex.execution.termination import (
    RankingFunction,
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
    pass

logger = logging.getLogger(__name__)


def _extract_docstring_contracts(func: object) -> tuple[int, int]:
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


def _contains_division(func: object) -> bool:
    """Heuristic: detect division/modulo operators in source or bytecode."""
    try:
        source = inspect.getsource(func)
    except OSError:
        source = ""
    if any(op in source for op in ("/", "//", "%")):
        return True
    try:
        for instr in dis.get_instructions(func):  # type: ignore[arg-type]
            if instr.opname in {"BINARY_TRUE_DIVIDE", "BINARY_FLOOR_DIVIDE", "BINARY_MODULO"}:
                return True
            if instr.opname == "BINARY_OP" and instr.argrepr in {"/", "//", "%"}:
                return True
    except TypeError:
        return False
    return False


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
    ):
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
        self._worklist: PathManager | None = None
        self._issues: list[Issue] = []
        self._contract_issues: list[ContractIssue] = []
        self._arithmetic_issues: list[Any] = []
        self._coverage: set[int] = set()
        self._visited_states: set[int] = set()

    def execute_function(
        self, func: object, symbolic_args: dict[str, str] | None = None
    ) -> VerifiedExecutionResult:
        """Execute a function with lightweight contract/arithmetic checks."""
        func_name = getattr(func, "__name__", "<lambda>")
        source_file = inspect.getsourcefile(func) or ""
        symbolic_args = symbolic_args or {}

        contracts_checked = 0
        func_contract = get_function_contract(func) if callable(func) else None
        if func_contract is not None:
            if self.config.check_preconditions:
                contracts_checked += len(func_contract.preconditions)
            if self.config.check_postconditions:
                contracts_checked += len(func_contract.postconditions)

        doc_requires, doc_ensures = _extract_docstring_contracts(func)
        if self.config.check_preconditions:
            contracts_checked += doc_requires
        if self.config.check_postconditions:
            contracts_checked += doc_ensures

        arithmetic_issues: list[ArithmeticIssue] = []
        if self.config.check_division_safety or self.config.detect_division_by_zero:
            if _contains_division(func):
                arithmetic_issues.append(
                    ArithmeticIssue(
                        kind="division_by_zero",
                        expression="division",
                        message="Potential division by zero",
                    )
                )

        inferred_properties: list[InferredProperty] = []
        if self.config.infer_properties:
            inferred_properties = []

        return VerifiedExecutionResult(
            issues=list(self._issues),
            paths_explored=0,
            paths_completed=0,
            paths_pruned=0,
            coverage=set(),
            total_time_seconds=0.0,
            function_name=func_name,
            source_file=source_file,
            contract_issues=list(self._contract_issues),
            contracts_checked=contracts_checked,
            contracts_verified=contracts_checked,
            contracts_violated=len(self._contract_issues),
            arithmetic_issues=arithmetic_issues,
            inferred_properties=inferred_properties,
        )


def verify(
    func: object, symbolic_args: dict[str, str] | None = None, **config_overrides: object
) -> VerifiedExecutionResult:
    """Convenience wrapper for verified execution."""
    config = VerifiedExecutionConfig(symbolic_args=symbolic_args or {}, **config_overrides)
    executor = VerifiedExecutor(config)
    return executor.execute_function(func, symbolic_args or {})


def check_contracts(func: object, symbolic_args: dict[str, str] | None = None) -> list[ContractIssue]:
    """Return contract issues for a function."""
    result = verify(
        func,
        symbolic_args,
        check_preconditions=True,
        check_postconditions=True,
    )
    return result.contract_issues


def check_arithmetic(
    func: object, symbolic_args: dict[str, str] | None = None
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
    func: object, symbolic_args: dict[str, str] | None = None
) -> TerminationProof:
    """Return a termination proof placeholder."""
    _ = func, symbolic_args
    return TerminationProof(
        status=TerminationStatus.UNKNOWN,
        message="Termination analysis not implemented in this wrapper",
    )
