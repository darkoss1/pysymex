"""Verified symbolic executor with integrated contract and property checking.

This module integrates symbolic execution with formal verification:
- Checks @requires preconditions before function execution
- Verifies @ensures postconditions on all execution paths
- Validates loop invariants inductively
- Proves termination using ranking functions
- Infers and verifies properties from execution traces

Implementation split across:
- termination.py: TerminationStatus, RankingFunction, TerminationProof, TerminationAnalyzer
- verified_execution_models.py: VerifiedExecutionConfig, ContractIssue, ArithmeticIssue, InferredProperty, VerifiedExecutionResult
- verified_executor.py: VerifiedExecutor class + convenience functions
"""

from __future__ import annotations


import dis

import inspect

import logging

import types

from collections.abc import Callable

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

logger = logging.getLogger(__name__)

from typing import (
    Any,
    cast,
)


import z3


from pysymex._compat import get_starts_line

from pysymex.analysis.contracts import (
    ContractKind,
    ContractVerifier,
    FunctionContract,
    VerificationResult,
)

from pysymex.analysis.detectors import DetectorRegistry, Issue, default_registry

from pysymex.analysis.path_manager import (
    PathManager,
    create_path_manager,
)

from pysymex.analysis.properties import (
    ArithmeticVerifier,
    ProofStatus,
    PropertyKind,
    PropertyProver,
)

from pysymex.core.solver import ShadowSolver, is_satisfiable

from pysymex.core.state import VMState

from pysymex.core.types import SymbolicList, SymbolicString, SymbolicValue

from pysymex.execution.dispatcher import OpcodeDispatcher


import pysymex.execution.opcodes


from .termination import (
    RankingFunction,
    TerminationAnalyzer,
    TerminationProof,
    TerminationStatus,
)


from .verified_execution_models import (
    ArithmeticIssue,
    ContractIssue,
    InferredProperty,
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
)


class VerifiedExecutor:
    """Symbolic executor with integrated contract and property verification.
    This executor extends symbolic execution with:
    1. Precondition checking on function entry
    2. Postcondition verification on all return paths
    3. Loop invariant validation
    4. Termination analysis with ranking functions
    5. Arithmetic safety verification
    6. Property inference from execution traces
    """

    def __init__(
        self,
        config: VerifiedExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
    ):
        self.config = config or VerifiedExecutionConfig()

        self.detector_registry = detector_registry or default_registry

        self.dispatcher = OpcodeDispatcher()

        self.solver = ShadowSolver(timeout_ms=self.config.solver_timeout_ms)

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

        self._arithmetic_issues: list[ArithmeticIssue] = []

        self._coverage: set[int] = set()

        self._visited_states: set[int] = set()

        self._function_contract: FunctionContract | None = None

        self._z3_symbols: dict[str, z3.ExprRef] = {}

        self._initial_values: dict[str, z3.ExprRef] = {}

        self._return_values: list[tuple[VMState, Any]] = []

        self._loop_heads: set[int] = set()

        self._loop_iterations: dict[int, int] = {}

        self._paths_explored: int = 0

        self._paths_completed: int = 0

        self._paths_pruned: int = 0

        self._iterations: int = 0

        self._contracts_checked: int = 0

        self._contracts_verified: int = 0

        self._contracts_violated: int = 0

    def execute_function(
        self,
        func: Callable[..., Any],
        symbolic_args: dict[str, str] | None = None,
    ) -> VerifiedExecutionResult:
        """
        Execute a function with full verification.
        Args:
            func: The function to analyze
            symbolic_args: Mapping of parameter names to types
        Returns:
            VerifiedExecutionResult with issues and verification status
        """

        import time

        start_time = time.time()

        self._reset()

        self._function_contract = self._extract_contracts(func)

        original_func = func

        while hasattr(func, "__wrapped__"):
            func = cast(Any, func).__wrapped__

        code = func.__code__

        self._instructions = _cached_get_instructions(code)

        self.dispatcher.set_instructions(self._instructions)

        self._build_line_mapping(code)

        self._detect_loops()

        initial_state = self._create_initial_state(func, symbolic_args or {})

        self._initial_values = dict(self._z3_symbols)

        if self.config.check_preconditions and self._function_contract:
            self._verify_preconditions(initial_state)

        self._worklist = create_path_manager(self.config.strategy)

        self._worklist.add_state(initial_state)

        self._execute_loop()

        if self.config.check_postconditions and self._function_contract:
            self._verify_postconditions()

        termination_proof = None

        if self.config.check_termination:
            if self._loop_heads:
                termination_proof = self._analyze_termination()

            else:
                termination_proof = TerminationProof(
                    status=TerminationStatus.TERMINATES,
                    message="No loops detected - trivially terminates",
                )

        inferred_properties = []

        if self.config.infer_properties:
            inferred_properties = self._infer_properties()

        end_time = time.time()

        result = VerifiedExecutionResult(
            issues=self._issues,
            paths_explored=self._paths_explored,
            paths_completed=self._paths_completed,
            paths_pruned=self._paths_pruned,
            coverage=self._coverage,
            total_time_seconds=end_time - start_time,
            function_name=original_func.__name__,
            source_file=code.co_filename,
            contract_issues=self._contract_issues,
            contracts_checked=self._contracts_checked,
            contracts_verified=self._contracts_verified,
            contracts_violated=self._contracts_violated,
            arithmetic_issues=self._arithmetic_issues,
            termination_proof=termination_proof,
            inferred_properties=inferred_properties,
        )

        return result

    def _reset(self) -> None:
        """Reset execution state."""

        self._instructions = []

        self._pc_to_line = {}

        self._issues = []

        self._contract_issues = []

        self._arithmetic_issues = []

        self._coverage = set()

        self._visited_states = set()

        self._paths_explored = 0

        self._paths_completed = 0

        self._paths_pruned = 0

        self._iterations = 0

        self._contracts_checked = 0

        self._contracts_verified = 0

        self._contracts_violated = 0

        self._function_contract = None

        self._z3_symbols = {}

        self._initial_values = {}

        self._return_values = []

        self._loop_heads = set()

        self._loop_iterations = {}

    def _build_line_mapping(self, code: types.CodeType) -> None:
        """Build mapping from PC to source line numbers."""

        last_line = None

        for i, instr in enumerate(self._instructions):
            if hasattr(instr, "positions") and instr.positions:
                line = instr.positions.lineno

                if line:
                    self._pc_to_line[i] = line

                    last_line = line

                elif last_line:
                    self._pc_to_line[i] = last_line

            elif (line := get_starts_line(instr)) is not None:
                self._pc_to_line[i] = line

                last_line = line

            elif last_line:
                self._pc_to_line[i] = last_line

    def _detect_loops(self) -> None:
        """Detect loop headers in bytecode."""

        offset_to_idx: dict[int, int] = {}

        for i, instr in enumerate(self._instructions):
            offset_to_idx[instr.offset] = i

        for i, instr in enumerate(self._instructions):
            if instr.opname in ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"):
                target_offset: Any = instr.argval

                if target_offset in offset_to_idx:
                    target_pc: int = offset_to_idx[target_offset]

                    self._loop_heads.add(target_pc)

            elif instr.opname == "FOR_ITER":
                self._loop_heads.add(i)

    def _extract_contracts(self, func: Callable[..., Any]) -> FunctionContract:
        """Extract contracts from function decorators and annotations."""

        contract = FunctionContract(function_name=func.__name__)

        if hasattr(func, "__contract__"):
            existing = cast(Any, func).__contract__

            for pre in existing.preconditions:
                contract.preconditions.append(pre)

            for post in existing.postconditions:
                contract.postconditions.append(post)

            for pc, invs in existing.loop_invariants.items():
                contract.loop_invariants[pc] = invs

        if hasattr(func, "__requires__"):
            for req in cast(Any, func).__requires__:
                contract.add_precondition(
                    req.condition,
                    req.message,
                    req.line_number,
                )

        if hasattr(func, "__ensures__"):
            for ens in cast(Any, func).__ensures__:
                contract.add_postcondition(
                    ens.condition,
                    ens.message,
                    ens.line_number,
                )

        if hasattr(func, "__self__") and hasattr(
            cast(Any, func).__self__.__class__, "__invariants__"
        ):
            for inv in cast(Any, func).__self__.__class__.__invariants__:
                contract.add_precondition(inv.condition, inv.message, inv.line_number)

                contract.add_postcondition(inv.condition, inv.message, inv.line_number)

        if func.__doc__:
            contract = self._parse_docstring_contracts(func.__doc__, contract)

        return contract

    def _parse_docstring_contracts(
        self,
        docstring: str,
        contract: FunctionContract,
    ) -> FunctionContract:
        """Parse contracts from docstring.
        Supports:
            :requires: condition
            :ensures: condition
            :invariant: condition
        """

        import re

        for match in re.finditer(r":requires:\s*(.+?)(?:\n|$)", docstring):
            contract.add_precondition(match.group(1).strip())

        for match in re.finditer(r":ensures:\s*(.+?)(?:\n|$)", docstring):
            contract.add_postcondition(match.group(1).strip())

        return contract

    def _create_initial_state(
        self,
        func: Callable[..., Any],
        symbolic_args: dict[str, str],
    ) -> VMState:
        """Create initial VM state with symbolic arguments."""

        state = VMState()

        try:
            sig = inspect.signature(func)

            params = list(sig.parameters.keys())

        except (ValueError, TypeError):
            params = list(func.__code__.co_varnames[: func.__code__.co_argcount])

        for param in params:
            type_hint = symbolic_args.get(param, "int")

            sym_val = self._create_symbolic_for_type(param, type_hint)

            state.local_vars[param] = sym_val

            if hasattr(sym_val, "z3_int"):
                self._z3_symbols[param] = sym_val.z3_int

            elif hasattr(sym_val, "z3_expr"):
                self._z3_symbols[param] = sym_val.z3_expr

            elif isinstance(sym_val, z3.ExprRef):
                self._z3_symbols[param] = sym_val

            else:
                self._z3_symbols[param] = z3.Int(f"{param}_int")

        return state

    def _create_symbolic_for_type(self, name: str, type_hint: str) -> Any:
        """Create a symbolic value of the given type."""

        type_hint = type_hint.lower()

        if type_hint in ("int", "integer"):
            val, _constraint = SymbolicValue.symbolic(name)

            return val

        elif type_hint in ("str", "string"):
            val, _constraint = SymbolicString.symbolic(name)

            return val

        elif type_hint in ("list", "array"):
            val, _constraint = SymbolicList.symbolic(name)

            return val

        elif type_hint in ("bool", "boolean"):
            val, _constraint = SymbolicValue.symbolic(name)

            return val

        else:
            val, _constraint = SymbolicValue.symbolic(name)

            return val

    def _verify_preconditions(self, initial_state: VMState) -> None:
        """Verify all preconditions at function entry."""

        assert self._function_contract is not None

        for contract in self._function_contract.preconditions:
            self._contracts_checked += 1

            result, counterexample = self.contract_verifier.verify_precondition(
                contract,
                list(initial_state.path_constraints),
                self._z3_symbols,
            )

            if result == VerificationResult.VERIFIED:
                self._contracts_verified += 1

            elif result == VerificationResult.VIOLATED or result == VerificationResult.UNREACHABLE:
                self._contracts_violated += 1

                self._contract_issues.append(
                    ContractIssue(
                        kind=contract.kind,
                        condition=contract.condition,
                        message=f"Precondition may not be satisfiable: {contract.condition}",
                        line_number=contract.line_number,
                        function_name=self._function_contract.function_name,
                        counterexample=counterexample or {},
                        result=result,
                    )
                )

    def _verify_postconditions(self) -> None:
        """Verify postconditions on all collected return paths."""

        assert self._function_contract is not None

        for contract in self._function_contract.postconditions:
            self._contracts_checked += 1

            contract_violated = False

            contract_counterexample: dict[str, Any] | None = None

            for state, return_val in self._return_values:
                extended_symbols = dict(self._z3_symbols)

                for name, val in self._initial_values.items():
                    extended_symbols[f"old_{name}"] = val

                if isinstance(return_val, z3.ExprRef):
                    extended_symbols["__result__"] = return_val

                elif hasattr(return_val, "z3_int"):
                    extended_symbols["__result__"] = return_val.z3_int

                elif hasattr(return_val, "z3_expr"):
                    extended_symbols["__result__"] = return_val.z3_expr

                path_constraints = list(state.path_constraints)

                result, counterexample = self.contract_verifier.verify_postcondition(
                    contract,
                    self._function_contract.preconditions,
                    path_constraints,
                    extended_symbols,
                )

                if result == VerificationResult.VIOLATED:
                    contract_violated = True

                    contract_counterexample = counterexample

                    break

            if contract_violated:
                self._contracts_violated += 1

                self._contract_issues.append(
                    ContractIssue(
                        kind=contract.kind,
                        condition=contract.condition,
                        message=f"Postcondition may be violated: {contract.condition}",
                        line_number=contract.line_number,
                        function_name=self._function_contract.function_name,
                        counterexample=contract_counterexample or {},
                        result=VerificationResult.VIOLATED,
                    )
                )

            elif not self._return_values:
                pass

            else:
                self._contracts_verified += 1

    def _execute_loop(self) -> None:
        """Main execution loop."""

        assert self._worklist is not None

        while not self._worklist.is_empty():
            if self._iterations >= self.config.max_iterations:
                break

            if self._paths_explored >= self.config.max_paths:
                break

            state = self._worklist.get_next_state()

            if state is None:
                break

            self._iterations += 1

            self._execute_step(state)

    def _execute_step(self, state: VMState) -> None:
        """Execute a single step with verification checks."""

        if state.pc >= len(self._instructions):
            self._paths_completed += 1

            return

        if state.depth > self.config.max_depth:
            self._paths_pruned += 1

            return

        state_hash = self._hash_state(state)

        if state_hash in self._visited_states:
            self._paths_pruned += 1

            return

        self._visited_states.add(state_hash)

        instr = self._instructions[state.pc]

        self._coverage.add(state.pc)

        state.visited_pcs.add(state.pc)

        if not is_satisfiable(list(state.path_constraints)):
            self._paths_pruned += 1

            return

        if state.pc in self._loop_heads and self.config.check_loop_invariants:
            self._check_loop_invariants(state)

        if self.config.check_overflow or self.config.check_division_safety:
            self._check_arithmetic_safety(state, instr)

        self._run_detectors(state, instr)

        try:
            result = self.dispatcher.dispatch(instr, state)

        except Exception as e:
            if self.config.verbose:
                print(f"Execution error at PC {state.pc}: {e}")

            self._paths_pruned += 1

            return

        if result.issues:
            for issue in result.issues:
                issue.line_number = self._pc_to_line.get(state.pc)

                self._issues.append(issue)

        if result.terminal:
            self._paths_completed += 1

            if instr.opname in ("RETURN_VALUE", "RETURN_CONST"):
                return_val = state.stack[-1] if state.stack else None

                self._return_values.append((state, return_val))

            return

        for new_state in result.new_states:
            new_state.depth = state.depth + 1

            if self._worklist is not None:
                self._worklist.add_state(new_state)

            self._paths_explored += 1

    def _check_loop_invariants(self, state: VMState) -> None:
        """Check loop invariants at loop header."""

        if not self._function_contract:
            return

        pc = state.pc

        if pc not in self._function_contract.loop_invariants:
            return

        for contract in self._function_contract.loop_invariants[pc]:
            self._contracts_checked += 1

            current_symbols = dict(self._z3_symbols)

            for name, val in state.local_vars.items():
                if isinstance(val, z3.ExprRef):
                    current_symbols[name] = val

                elif hasattr(val, "z3_expr"):
                    current_symbols[name] = val.z3_expr

            result, counterexample = self.contract_verifier.verify_precondition(
                contract,
                list(state.path_constraints),
                current_symbols,
            )

            if result == VerificationResult.VERIFIED:
                self._contracts_verified += 1

            elif result == VerificationResult.VIOLATED:
                self._contracts_violated += 1

                self._contract_issues.append(
                    ContractIssue(
                        kind=ContractKind.LOOP_INVARIANT,
                        condition=contract.condition,
                        message=f"Loop invariant may be violated: {contract.condition}",
                        line_number=contract.line_number or self._pc_to_line.get(pc),
                        function_name=self._function_contract.function_name,
                        counterexample=counterexample or {},
                        result=result,
                    )
                )

    def _check_arithmetic_safety(self, state: VMState, instr: dis.Instruction) -> None:
        """Check for arithmetic safety issues."""

        variables = dict(self._z3_symbols)

        for name, val in state.local_vars.items():
            if isinstance(val, z3.ExprRef):
                variables[name] = val

            elif hasattr(val, "z3_expr"):
                variables[name] = val.z3_expr

        if instr.opname == "BINARY_OP" and instr.arg == 11:
            if len(state.stack) >= 2:
                dividend = state.stack[-2]

                divisor = state.stack[-1]

                if isinstance(divisor, z3.ArithRef):
                    if not isinstance(dividend, z3.ArithRef):
                        dividend = z3.IntVal(0)

                    proof = self.arithmetic_verifier.check_division_safe(
                        dividend,
                        divisor,
                        variables,
                        list(state.path_constraints),
                    )

                    if proof.status != ProofStatus.PROVEN:
                        self._arithmetic_issues.append(
                            ArithmeticIssue(
                                kind="division_by_zero",
                                expression=str(divisor),
                                message="Division may fail: divisor could be zero",
                                line_number=self._pc_to_line.get(state.pc),
                                counterexample=(
                                    proof.counterexample if proof.counterexample is not None else {}
                                ),
                            )
                        )

        if self.config.check_overflow and instr.opname == "BINARY_OP":
            if len(state.stack) >= 2:
                left = state.stack[-2]

                right = state.stack[-1]

                if isinstance(left, z3.ArithRef) and isinstance(right, z3.ArithRef):
                    op_map = {0: "+", 1: "-", 5: "*"}

                    op = op_map.get(instr.arg or 0, "+")

                    if op == "+":
                        result_expr = left + right

                    elif op == "-":
                        result_expr = left - right

                    elif op == "*":
                        result_expr = left * right

                    else:
                        return

                    proof = self.arithmetic_verifier.check_overflow(
                        result_expr,
                        variables,
                        list(state.path_constraints),
                    )

                    if proof.status != ProofStatus.PROVEN:
                        self._arithmetic_issues.append(
                            ArithmeticIssue(
                                kind="overflow",
                                expression=f"{left} {op} {right}",
                                message="Operation may overflow",
                                line_number=self._pc_to_line.get(state.pc),
                                counterexample=(
                                    proof.counterexample if proof.counterexample is not None else {}
                                ),
                            )
                        )

    def _run_detectors(self, state: VMState, instr: dis.Instruction) -> None:
        """Run enabled detectors on current state."""

        for detector in self.detector_registry.get_all():
            if detector is None:
                continue

            if detector.name == "division-by-zero" and not self.config.detect_division_by_zero:
                continue

            if detector.name == "assertion-error" and not self.config.detect_assertion_errors:
                continue

            if detector.name == "index-error" and not self.config.detect_index_errors:
                continue

            if detector.name == "type-error" and not self.config.detect_type_errors:
                continue

            if detector.name == "overflow" and not self.config.detect_overflow:
                continue

            issue = detector.check(state, instr, is_satisfiable)

            if issue:
                issue.line_number = self._pc_to_line.get(state.pc)

                self._issues.append(issue)

    def _analyze_termination(self) -> TerminationProof:
        """Analyze termination of loops in the function."""

        if not self._loop_heads:
            return TerminationProof(
                status=TerminationStatus.TERMINATES, message="No loops detected"
            )

        for loop_pc in self._loop_heads:
            proof = self._analyze_single_loop(loop_pc)

            if proof.status == TerminationStatus.NON_TERMINATING:
                return proof

        all_terminate = True

        for loop_pc in self._loop_heads:
            proof = self._analyze_single_loop(loop_pc)

            if proof.status != TerminationStatus.TERMINATES:
                all_terminate = False

                break

        if all_terminate:
            return TerminationProof(
                status=TerminationStatus.TERMINATES,
                message=f"All {len(self._loop_heads)} loops terminate",
            )

        return TerminationProof(
            status=TerminationStatus.UNKNOWN,
            message=f"Could not prove termination for {len(self._loop_heads)} loops",
        )

    def _analyze_single_loop(self, loop_pc: int) -> TerminationProof:
        """Analyze a single loop for termination."""

        loop_info = self._extract_loop_info(loop_pc)

        if loop_info is None:
            return TerminationProof(
                status=TerminationStatus.UNKNOWN, message="Could not extract loop structure"
            )

        if len(loop_info) == 4:
            loop_var, loop_condition, loop_update, bound_var = loop_info

        else:
            loop_var, loop_condition, loop_update = loop_info

            bound_var = None

        symbols = dict(self._z3_symbols)

        if loop_var and loop_var not in symbols:
            symbols[loop_var] = z3.Int(f"{loop_var}_int")

        if loop_var and loop_var in symbols:
            var_z3 = symbols[loop_var]

            analyzer = TerminationAnalyzer(self.config.termination_timeout_ms)

            loop_body_effect: dict[str, z3.ExprRef] = {}

            if loop_update == "decrement":
                loop_body_effect[loop_var] = var_z3 - 1

            elif loop_update == "increment":
                loop_body_effect[loop_var] = var_z3 + 1

            if loop_condition == "greater_than_zero":
                z3_condition = var_z3 > 0

                return analyzer._synthesize_ranking(
                    z3_condition,
                    loop_body_effect,
                    symbols,
                )

            elif loop_condition == "less_than_bound" and bound_var and bound_var in symbols:
                bound_z3 = symbols[bound_var]

                z3_condition = var_z3 < bound_z3

                ranking = RankingFunction(
                    name=f"rank_{bound_var}_minus_{loop_var}",
                    expression=f"{bound_var} - {loop_var}",
                    z3_expr=bound_z3 - var_z3,
                    variables=[bound_var, loop_var],
                )

                return analyzer._verify_ranking_function(
                    z3_condition,
                    loop_body_effect,
                    symbols,
                    ranking,
                )

            else:
                z3_condition = z3.Bool(f"loop_cond_{loop_pc}")

                return analyzer._synthesize_ranking(
                    z3_condition,
                    loop_body_effect,
                    self._z3_symbols,
                )

        return TerminationProof(
            status=TerminationStatus.UNKNOWN, message="Could not identify loop variable"
        )

    def _extract_loop_info(
        self, loop_pc: int
    ) -> tuple[str, str, str, str | None] | tuple[str, str, str] | None:
        """Extract loop variable, condition type, and update type.
        Returns (variable_name, condition_type, update_type[, bound_var]) or None.
        condition_type: 'greater_than_zero', 'less_than_bound', etc.
        update_type: 'decrement', 'increment', etc.
        """

        if loop_pc >= len(self._instructions):
            return None

        loop_var = None

        bound_var = None

        condition_type = None

        update_type = None

        for i in range(loop_pc, max(0, loop_pc - 10), -1):
            instr = self._instructions[i]

            if instr.opname == "COMPARE_OP":
                if i >= 2:
                    load_instr = self._instructions[i - 1]

                    if load_instr.opname == "LOAD_FAST_LOAD_FAST":
                        names: Any = load_instr.argval

                        if isinstance(names, tuple) and len(names) >= 2:
                            loop_var = str(names[0])

                            bound_var = str(names[1])

                    else:
                        load_instr = self._instructions[i - 2]

                        if load_instr.opname in ("LOAD_FAST", "LOAD_FAST_CHECK"):
                            loop_var = str(load_instr.argval)

                        const_instr = self._instructions[i - 1]

                        if const_instr.opname == "LOAD_CONST" and const_instr.argval == 0:
                            pass

                        elif const_instr.opname in ("LOAD_FAST", "LOAD_FAST_CHECK"):
                            bound_var = str(const_instr.argval)

                    cmp = str(instr.argrepr) if instr.argrepr else str(instr.argval)

                    if ">" in cmp and bound_var is None:
                        condition_type = "greater_than_zero"

                    elif "<" in cmp and bound_var:
                        condition_type = "less_than_bound"

                break

        if not loop_var:
            return None

        for i in range(loop_pc, min(len(self._instructions), loop_pc + 20)):
            instr = self._instructions[i]

            if instr.opname == "STORE_FAST" and str(instr.argval) == loop_var:
                if i >= 1:
                    op_instr = self._instructions[i - 1]

                    if op_instr.opname == "BINARY_OP":
                        op = str(op_instr.argrepr)

                        if "-" in op:
                            update_type = "decrement"

                        elif "+" in op:
                            update_type = "increment"

                break

        if loop_var and condition_type and update_type:
            return (loop_var, condition_type, update_type, bound_var)

        if loop_var:
            return (loop_var, condition_type or "unknown", update_type or "unknown", bound_var)

        return None

    def _infer_properties(self) -> list[InferredProperty]:
        """Infer properties from execution traces."""

        properties: list[InferredProperty] = []

        if len(self._z3_symbols) == 2:
            names = list(self._z3_symbols.keys())

            a = self._z3_symbols[names[0]]

            b = self._z3_symbols[names[1]]

            if isinstance(a, z3.ArithRef) and isinstance(b, z3.ArithRef):
                properties.append(
                    InferredProperty(
                        kind=PropertyKind.COMMUTATIVITY,
                        description=f"Function may be commutative in {names[0]}, {names[1]}",
                        confidence=0.5,
                    )
                )

        return properties

    def _hash_state(self, state: VMState) -> int:
        """Create a hash for loop detection."""

        return hash(
            (
                state.pc,
                len(state.path_constraints),
                len(state.stack),
                tuple(sorted(state.local_vars.keys())),
            )
        )


def verify(
    func: Callable[..., Any],
    symbolic_args: dict[str, str] | None = None,
    **config_kwargs: Any,
) -> VerifiedExecutionResult:
    """
    Verify a function with contracts and arithmetic checks.
    Args:
        func: Function to verify
        symbolic_args: Mapping of parameter names to types
        **config_kwargs: Additional configuration options
    Returns:
        VerifiedExecutionResult with verification status
    Example:
        >>> @requires("x > 0")
        ... @ensures("result() >= x")
        ... def sqrt(x):
        ...     return x ** 0.5
        >>> result = verify(sqrt, {"x": "int"})
        >>> print(result.is_verified)
    """

    config = VerifiedExecutionConfig(**config_kwargs)

    executor = VerifiedExecutor(config)

    return executor.execute_function(func, symbolic_args)


def check_contracts(
    func: Callable[..., Any], symbolic_args: dict[str, str] | None = None
) -> list[ContractIssue]:
    """
    Check function contracts.
    Args:
        func: Function to check
        symbolic_args: Mapping of parameter names to types
    Returns:
        List of contract issues found
    """

    result = verify(
        func,
        symbolic_args,
        check_preconditions=True,
        check_postconditions=True,
        check_overflow=False,
        check_division_safety=False,
    )

    return result.contract_issues


def check_arithmetic(
    func: Callable[..., Any], symbolic_args: dict[str, str] | None = None
) -> list[ArithmeticIssue]:
    """
    Check function for arithmetic issues.
    Args:
        func: Function to check
        symbolic_args: Mapping of parameter names to types
    Returns:
        List of arithmetic issues found
    """

    result = verify(
        func,
        symbolic_args,
        check_preconditions=False,
        check_postconditions=False,
        check_overflow=True,
        check_division_safety=True,
    )

    return result.arithmetic_issues


def prove_termination(
    func: Callable[..., Any],
    symbolic_args: dict[str, str] | None = None,
) -> TerminationProof:
    """
    Attempt to prove function termination.
    Args:
        func: Function to analyze
        symbolic_args: Mapping of parameter names to types
    Returns:
        TerminationProof with status
    """

    result = verify(
        func,
        symbolic_args,
        check_termination=True,
        check_preconditions=False,
        check_postconditions=False,
    )

    return result.termination_proof or TerminationProof(
        status=TerminationStatus.UNKNOWN, message="No termination analysis performed"
    )
