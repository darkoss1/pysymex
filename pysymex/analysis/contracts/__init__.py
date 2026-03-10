"""Contract-based verification for pysymex.

This module provides formal verification through contracts.

Implementation split for maintainability:
- contracts_types: ContractKind, VerificationResult, ContractViolation, Contract, FunctionContract
- contract_compiler: ContractCompiler (AST -> Z3)
- contract_decorators: @requires, @ensures, @invariant, @loop_invariant
- This file (hub): ContractVerifier, VerificationReport, ContractAnalyzer
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import z3

from pysymex.analysis.contracts.compiler import ContractCompiler
from pysymex.analysis.contracts.decorators import (
    ensures,
    function_contracts,
    get_function_contract,
    invariant,
    loop_invariant,
    requires,
)
from pysymex.analysis.contracts.types import (
    Contract,
    ContractKind,
    ContractViolation,
    FunctionContract,
    VerificationResult,
)

logger = logging.getLogger(__name__)


class ContractVerifier:
    """Verifies function contracts using symbolic execution.
    Uses Z3 to prove:
    1. Preconditions are satisfiable (function can be called)
    2. Postconditions hold given preconditions (function is correct)
    3. Loop invariants are preserved
    """

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)

    def verify_precondition(
        self,
        contract: Contract,
        path_constraints: list[z3.BoolRef],
        symbols: dict[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify that precondition can be satisfied.
        Returns (result, counterexample if violated).
        """
        self._solver.reset()
        for pc in path_constraints:
            self._solver.add(pc)
        pre_expr = contract.compile(symbols)
        self._solver.push()
        self._solver.add(pre_expr)
        result = self._solver.check()
        self._solver.pop()
        if result == z3.sat:
            return VerificationResult.VERIFIED, None
        elif result == z3.unsat:
            return VerificationResult.UNREACHABLE, None
        else:
            return VerificationResult.UNKNOWN, None

    def verify_postcondition(
        self,
        contract: Contract,
        preconditions: list[Contract],
        path_constraints: list[z3.BoolRef],
        symbols: dict[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify that postcondition holds given preconditions.
        Uses Hoare logic: {P} code {Q} is valid if P ∧ path → Q
        """
        self._solver.reset()
        for pre in preconditions:
            pre_expr = pre.compile(symbols)
            self._solver.add(pre_expr)
        for pc in path_constraints:
            self._solver.add(pc)
        post_expr = contract.compile(symbols)
        self._solver.add(z3.Not(post_expr))
        result = self._solver.check()
        if result == z3.unsat:
            return VerificationResult.VERIFIED, None
        elif result == z3.sat:
            model = self._solver.model()
            counterexample = self._extract_counterexample(model, symbols)
            return VerificationResult.VIOLATED, counterexample
        else:
            return VerificationResult.UNKNOWN, None

    def verify_loop_invariant(
        self,
        invariant: Contract,
        loop_condition: z3.BoolRef,
        loop_body_constraints: list[z3.BoolRef],
        pre_loop_constraints: list[z3.BoolRef],
        symbols: dict[str, z3.ExprRef],
        symbols_after: dict[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify loop invariant using induction.
        1. Base case: Invariant holds on loop entry
        2. Inductive case: If invariant holds and loop condition is true,
           invariant still holds after loop body
        """
        self._solver.reset()
        for pc in pre_loop_constraints:
            self._solver.add(pc)
        inv_expr = invariant.compile(symbols)
        self._solver.add(z3.Not(inv_expr))
        base_result = self._solver.check()
        if base_result == z3.sat:
            model = self._solver.model()
            return VerificationResult.VIOLATED, self._extract_counterexample(model, symbols)
        self._solver.reset()
        self._solver.add(inv_expr)
        self._solver.add(loop_condition)
        for bc in loop_body_constraints:
            self._solver.add(bc)
        inv_after = invariant.compile(symbols_after)
        self._solver.add(z3.Not(inv_after))
        inductive_result = self._solver.check()
        if inductive_result == z3.sat:
            model = self._solver.model()
            return VerificationResult.VIOLATED, self._extract_counterexample(model, symbols)
        elif inductive_result == z3.unsat and base_result == z3.unsat:
            return VerificationResult.VERIFIED, None
        else:
            return VerificationResult.UNKNOWN, None

    def verify_assertion(
        self,
        condition: z3.BoolRef,
        path_constraints: list[z3.BoolRef],
        symbols: dict[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify an inline assertion."""
        self._solver.reset()
        for pc in path_constraints:
            self._solver.add(pc)
        self._solver.add(z3.Not(condition))
        result = self._solver.check()
        if result == z3.unsat:
            return VerificationResult.VERIFIED, None
        elif result == z3.sat:
            model = self._solver.model()
            counterexample = self._extract_counterexample(model, symbols)
            return VerificationResult.VIOLATED, counterexample
        else:
            return VerificationResult.UNKNOWN, None

    def _extract_counterexample(
        self,
        model: z3.ModelRef,
        symbols: dict[str, z3.ExprRef],
    ) -> dict[str, object]:
        """Extract counterexample values from Z3 model."""
        counterexample: dict[str, object] = {}
        for name, expr in symbols.items():
            if name.startswith("old_") or name == "__result__":
                continue
            try:
                val = model.eval(expr, model_completion=True)
                if z3.is_int_value(val):
                    counterexample[name] = val.as_long()
                elif z3.is_rational_value(val):
                    counterexample[name] = float(val.as_fraction())
                elif z3.is_true(val):
                    counterexample[name] = True
                elif z3.is_false(val):
                    counterexample[name] = False
                else:
                    counterexample[name] = str(val)
            except z3.Z3Exception:
                logger.debug("Model eval failed for variable %s", name, exc_info=True)
        return counterexample


@dataclass
class VerificationReport:
    """Report of contract verification results."""

    function_name: str
    total_contracts: int = 0
    verified: int = 0
    violated: int = 0
    unknown: int = 0
    violations: list[ContractViolation] = field(default_factory=list[ContractViolation])

    @property
    def is_verified(self) -> bool:
        """Check if all contracts were verified."""
        return self.violated == 0 and self.unknown == 0

    @property
    def has_violations(self) -> bool:
        """Check if any violations were found."""
        return self.violated > 0

    def add_result(
        self,
        contract: Contract,
        result: VerificationResult,
        counterexample: dict[str, object] | None = None,
        function_name: str | None = None,
    ) -> None:
        """Add a verification result."""
        self.total_contracts += 1
        if result == VerificationResult.VERIFIED:
            self.verified += 1
        elif result == VerificationResult.VIOLATED:
            self.violated += 1
            self.violations.append(
                ContractViolation(
                    kind=contract.kind,
                    condition=contract.condition,
                    message=contract.message or contract.condition,
                    line_number=contract.line_number,
                    function_name=function_name,
                    counterexample=counterexample or {},
                )
            )
        else:
            self.unknown += 1

    def format(self) -> str:
        """Format report for display."""
        lines = [
            f"Verification Report: {self .function_name }",
            "=" * 50,
            f"Total contracts: {self .total_contracts }",
            f"  Verified: {self .verified }",
            f"  Violated: {self .violated }",
            f"  Unknown:  {self .unknown }",
        ]
        if self.is_verified:
            lines.append("\n✓ All contracts verified!")
        elif self.has_violations:
            lines.append("\n✗ Contract violations found:")
            for v in self.violations:
                lines.append("")
                lines.append(v.format())
        return "\n".join(lines)


class ContractAnalyzer:
    """Analyzes functions with contracts using symbolic execution.
    Integrates with PySyMex's symbolic execution engine to verify
    that contracts hold for all possible inputs.
    """

    def __init__(self, verifier: ContractVerifier | None = None):
        self.verifier = verifier or ContractVerifier()
        self._reports: dict[str, VerificationReport] = {}

        try:
            from pysymex.analysis.invariants import InvariantState

            self.invariant_state = InvariantState()
        except ImportError:
            logger.debug("Failed to import InvariantState", exc_info=True)
            self.invariant_state = None

    def analyze_function(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
    ) -> VerificationReport:
        """Analyze a function's contracts.
        Args:
            func: The function to analyze
            symbolic_args: Map of argument names to types ("int", "float", "bool")
        Returns:
            VerificationReport with verification results
        """
        contract = get_function_contract(func)
        report = VerificationReport(function_name=func.__name__)
        if contract is None:

            self._check_class_invariants(func, report, symbolic_args or {})
            return report
        symbols = self._build_symbols(func, symbolic_args or {})
        for pre in contract.preconditions:
            result, counter = self.verifier.verify_precondition(pre, [], symbols)
            report.add_result(pre, result, counter, func.__name__)
        for post in contract.postconditions:
            symbols_with_old = dict(symbols)
            for name, expr in symbols.items():
                old_name = f"old_{name }"
                if name.startswith("old_"):
                    continue
                if z3.is_int(expr):
                    symbols_with_old[old_name] = z3.Int(old_name)
                elif z3.is_real(expr):
                    symbols_with_old[old_name] = z3.Real(old_name)
                else:
                    symbols_with_old[old_name] = z3.Int(old_name)
            symbols_with_old["__result__"] = z3.Int("__result__")
            result, counter = self.verifier.verify_postcondition(
                post, contract.preconditions, [], symbols_with_old
            )
            report.add_result(post, result, counter, func.__name__)

        self._check_class_invariants(func, report, symbolic_args or {})
        self._reports[func.__name__] = report
        return report

    def _check_class_invariants(
        self,
        func: Callable[..., object],
        report: VerificationReport,
        symbolic_args: dict[str, str],
    ) -> None:
        """Check class invariants if func is a method on a class with __invariants__."""
        if self.invariant_state is None:
            return

        owner_class = getattr(func, "__self__", None)
        if owner_class is not None:
            owner_class = owner_class.__class__
        if owner_class is None:
            owner_class = getattr(func, "__qualname__", "")

            if "." in owner_class:

                return
            return
        if not hasattr(owner_class, "__invariants__"):
            return
        from pysymex.analysis.invariants import (
            get_invariants,
            parse_invariant_condition,
        )

        invariants = get_invariants(owner_class)
        if not invariants:
            return
        self.invariant_state.register_class(owner_class.__name__, invariants)
        symbols = self._build_symbols(func, symbolic_args)
        self_attrs: dict[str, z3.ExprRef] = {}
        for name, expr in symbols.items():
            self_attrs[f"self.{name }"] = expr
        z3_conditions = [parse_invariant_condition(inv.condition, self_attrs) for inv in invariants]
        checker = self.invariant_state.checker
        method_name = func.__name__
        when = "init" if method_name == "__init__" else "exit"
        violations = checker.check_all_invariants(invariants, z3_conditions, when, method_name)
        for violation in violations:
            self.invariant_state.record_violation(violation)
            inv_contract = Contract(
                kind=ContractKind.INVARIANT,
                condition=violation.invariant.condition,
                message=str(violation),
                line_number=None,
            )
            report.add_result(
                inv_contract,
                VerificationResult.VIOLATED,
                violation.counterexample,
                method_name,
            )

    def _build_symbols(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str],
    ) -> dict[str, z3.ExprRef]:
        """Build symbolic variables for function arguments."""
        symbols: dict[str, z3.ExprRef] = {}
        try:
            sig = inspect.signature(func)
            for param_name in sig.parameters:
                type_hint = symbolic_args.get(param_name, "int")
                if type_hint == "int":
                    symbols[param_name] = z3.Int(param_name)
                elif type_hint == "float" or type_hint == "real":
                    symbols[param_name] = z3.Real(param_name)
                elif type_hint == "bool":
                    symbols[param_name] = z3.Bool(param_name)
                else:
                    symbols[param_name] = z3.Int(param_name)
        except (ValueError, TypeError):
            logger.debug("Failed to build symbolic args for function", exc_info=True)
        return symbols

    def get_report(self, func_name: str) -> VerificationReport | None:
        """Get the verification report for a function."""
        return self._reports.get(func_name)

    def get_all_reports(self) -> list[VerificationReport]:
        """Get all verification reports."""
        return list(self._reports.values())


__all__ = [
    "Contract",
    "ContractAnalyzer",
    "ContractCompiler",
    "ContractKind",
    "ContractVerifier",
    "ContractViolation",
    "FunctionContract",
    "VerificationReport",
    "VerificationResult",
    "ensures",
    "get_function_contract",
    "invariant",
    "loop_invariant",
    "requires",
]
