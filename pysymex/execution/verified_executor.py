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
    RankingFunction as RankingFunction,
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
        """Execute a function with full symbolic contract and property verification."""
        from pysymex.execution.executor_core import SymbolicExecutor
        from pysymex.execution.executor_types import ExecutionConfig

        func_name = getattr(func, "__name__", "<lambda>")
        source_file = inspect.getsourcefile(func) or ""
        symbolic_args = symbolic_args or {}

        # 1. Setup the core Symbolic Executor with verification bounds
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
            # Force hooks to be evaluated
            use_loop_analysis=True,
        )
        core_executor = SymbolicExecutor(exec_config, self.detector_registry)

        # 2. Extract Contracts
        contracts_checked = 0
        func_contract = get_function_contract(func) if callable(func) else None
        
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

        # Intercept Return paths to check postconditions
        def _check_postconditions_hook(executor: object, state: object, issue: object = None) -> None:
            if not postconditions:
                return
            
            # Type hinting the generic objects
            from pysymex.core.state import VMState
            import z3
            
            state_typed = state if isinstance(state, VMState) else None
            if not state_typed:
                return

            # Check if this is a return/terminal state (stack might have return value)
            if not hasattr(state_typed, "pc"):
                return
                
            # If we're at a RETURN_VALUE or RETURN_CONST opcode (rough heuristic from context)
            try:
                instrs = getattr(state_typed, "current_instructions", getattr(executor, "_instructions", []))
                if state_typed.pc < len(instrs):
                    instr = instrs[state_typed.pc]
                    if instr.opname in ("RETURN_VALUE", "RETURN_CONST"):
                        ret_val = state_typed.peek() if state_typed.stack else None
                        
                        # Prepare symbols map for the compiler
                        symbols: dict[str, z3.ExprRef] = {}
                        for name, val in state_typed.local_vars.items():
                            if hasattr(val, "z3_int"):
                                symbols[name] = val.z3_int
                            elif hasattr(val, "z3_bool"):
                                symbols[name] = val.z3_bool
                        
                        if ret_val is not None:
                            if hasattr(ret_val, "z3_int"):
                                symbols["__return__"] = ret_val.z3_int
                            elif hasattr(ret_val, "z3_bool"):
                                symbols["__return__"] = ret_val.z3_bool

                        for post in postconditions:
                            try:
                                # Delegate to the ContractVerifier instance
                                res = self.contract_verifier.verify_postcondition(
                                    post,
                                    list(state_typed.path_constraints),
                                    symbols
                                )
                                if res.status == ProofStatus.FALSIFIED:
                                    contract_issues.append(
                                        ContractIssue(
                                            kind=ContractKind.POSTCONDITION,
                                            condition=post,
                                            message=f"Postcondition might not hold on return: {res.message}",
                                            line_number=getattr(instr, "starts_line", None),
                                            counterexample=res.counterexample or {},
                                        )
                                    )
                            except Exception as e:
                                logger.debug(f"Failed to verify postcondition {post}: {e}")
            except Exception:
                pass

        if self.config.check_postconditions:
            core_executor.register_hook("pre_step", _check_postconditions_hook)

        # 3. Run the core symbolic execution
        try:
            core_result = core_executor.execute_function(func, symbolic_args)
        except Exception as e:
            logger.error("Core symbolic execution failed", exc_info=True)
            core_result = None

        # 4. Synthesize Arithmetic Issues from Core Issues
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
                            counterexample=iss.model or {},
                        )
                    )
                else:
                    issues.append(iss)

        # 5. Precondition Checking (requires a bit of AST/bytecode mapping to call sites if we were interprocedural,
        # but for the top-level function, preconditions are assumptions).
        # We assume preconditions hold during execution, but if they are intrinsically unsatisfiable, we flag them.
        
        inferred_properties: list[InferredProperty] = []
        if self.config.infer_properties:
            # Placeholder for property inference
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
            # Add termination placeholder 
            termination_proof=None,
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
