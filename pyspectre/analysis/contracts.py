"""Contract-based verification for PySpectre.
This module provides formal verification through contracts:
- Preconditions (@requires): Conditions that must hold before function execution
- Postconditions (@ensures): Conditions that must hold after function execution
- Invariants (@invariant): Conditions that must hold throughout execution
- Loop invariants: Conditions preserved across loop iterations
Uses Z3 theorem prover to mathematically verify contract satisfaction.
"""

from __future__ import annotations
import ast
import functools
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
    Any,
)
import z3

if TYPE_CHECKING:
    pass


class ContractKind(Enum):
    """Types of contracts."""

    REQUIRES = auto()
    ENSURES = auto()
    INVARIANT = auto()
    LOOP_INVARIANT = auto()
    ASSERT = auto()
    ASSUME = auto()


class VerificationResult(Enum):
    """Result of contract verification."""

    VERIFIED = auto()
    VIOLATED = auto()
    UNKNOWN = auto()
    UNREACHABLE = auto()


@dataclass
class ContractViolation:
    """Represents a contract violation."""

    kind: ContractKind
    condition: str
    message: str
    line_number: int | None = None
    function_name: str | None = None
    counterexample: dict[str, Any] = field(default_factory=dict)

    def format(self) -> str:
        """Format violation for display."""
        location = f" at line {self.line_number}" if self.line_number else ""
        func = f" in {self.function_name}" if self.function_name else ""
        result = f"[{self.kind.name}]{func}{location}: {self.message}\n"
        result += f"  Condition: {self.condition}\n"
        if self.counterexample:
            result += "  Counterexample:\n"
            for var, val in self.counterexample.items():
                result += f"    {var} = {val}\n"
        return result


@dataclass
class Contract:
    """A single contract specification."""

    kind: ContractKind
    condition: str
    z3_expr: z3.BoolRef | None = None
    message: str | None = None
    line_number: int | None = None

    def compile(self, symbols: dict[str, z3.ExprRef]) -> z3.BoolRef:
        """Compile condition string to Z3 expression."""
        if self.z3_expr is not None:
            return self.z3_expr
        expr = ContractCompiler.compile_expression(self.condition, symbols)
        self.z3_expr = expr
        return expr


@dataclass
class FunctionContract:
    """Complete contract specification for a function."""

    function_name: str
    preconditions: list[Contract] = field(default_factory=list)
    postconditions: list[Contract] = field(default_factory=list)
    loop_invariants: dict[int, list[Contract]] = field(default_factory=dict)
    old_values: dict[str, str] = field(default_factory=dict)
    result_var: str = "__result__"

    def add_precondition(self, condition: str, message: str = None, line: int = None) -> None:
        """Add a precondition."""
        self.preconditions.append(
            Contract(
                kind=ContractKind.REQUIRES,
                condition=condition,
                message=message or f"Precondition: {condition}",
                line_number=line,
            )
        )

    def add_postcondition(self, condition: str, message: str = None, line: int = None) -> None:
        """Add a postcondition."""
        self.postconditions.append(
            Contract(
                kind=ContractKind.ENSURES,
                condition=condition,
                message=message or f"Postcondition: {condition}",
                line_number=line,
            )
        )

    def add_loop_invariant(
        self, pc: int, condition: str, message: str = None, line: int = None
    ) -> None:
        """Add a loop invariant at a specific program counter."""
        if pc not in self.loop_invariants:
            self.loop_invariants[pc] = []
        self.loop_invariants[pc].append(
            Contract(
                kind=ContractKind.LOOP_INVARIANT,
                condition=condition,
                message=message or f"Loop invariant: {condition}",
                line_number=line,
            )
        )


class ContractCompiler(ast.NodeVisitor):
    """Compiles Python expressions to Z3 constraints."""

    def __init__(self, symbols: dict[str, z3.ExprRef]):
        self.symbols = symbols
        self._old_prefix = "old_"

    @classmethod
    def compile_expression(cls, expr_str: str, symbols: dict[str, z3.ExprRef]) -> z3.BoolRef:
        """Compile a Python expression string to Z3."""
        try:
            tree = ast.parse(expr_str, mode="eval")
            compiler = cls(symbols)
            return compiler.visit(tree.body)
        except Exception:
            return z3.Bool(f"contract_{hash(expr_str)}")

    def visit_Compare(self, node: ast.Compare) -> z3.BoolRef:
        """Handle comparison operators."""
        left = self.visit(node.left)
        result = None
        current = left
        for op, comparator in zip(node.ops, node.comparators):
            right = self.visit(comparator)
            if isinstance(op, ast.Lt):
                cmp = current < right
            elif isinstance(op, ast.LtE):
                cmp = current <= right
            elif isinstance(op, ast.Gt):
                cmp = current > right
            elif isinstance(op, ast.GtE):
                cmp = current >= right
            elif isinstance(op, ast.Eq):
                cmp = current == right
            elif isinstance(op, ast.NotEq):
                cmp = current != right
            else:
                cmp = z3.Bool(f"cmp_{id(op)}")
            if result is None:
                result = cmp
            else:
                result = z3.And(result, cmp)
            current = right
        return result

    def visit_BoolOp(self, node: ast.BoolOp) -> z3.BoolRef:
        """Handle and/or operators."""
        values = [self.visit(v) for v in node.values]
        if isinstance(node.op, ast.And):
            return z3.And(*values)
        elif isinstance(node.op, ast.Or):
            return z3.Or(*values)
        else:
            return z3.Bool(f"boolop_{id(node)}")

    def visit_UnaryOp(self, node: ast.UnaryOp) -> z3.ExprRef:
        """Handle unary operators."""
        operand = self.visit(node.operand)
        if isinstance(node.op, ast.Not):
            return z3.Not(operand)
        elif isinstance(node.op, ast.USub):
            return -operand
        elif isinstance(node.op, ast.UAdd):
            return operand
        else:
            return operand

    def visit_BinOp(self, node: ast.BinOp) -> z3.ExprRef:
        """Handle binary operators."""
        left = self.visit(node.left)
        right = self.visit(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        elif isinstance(node.op, ast.Sub):
            return left - right
        elif isinstance(node.op, ast.Mult):
            return left * right
        elif isinstance(node.op, ast.Div):
            return left / right
        elif isinstance(node.op, ast.FloorDiv):
            return left / right
        elif isinstance(node.op, ast.Mod):
            return left % right
        elif isinstance(node.op, ast.Pow):
            if isinstance(node.right, ast.Constant) and isinstance(node.right.value, int):
                if node.right.value == 2:
                    return left * left
                elif node.right.value == 3:
                    return left * left * left
            return z3.Int(f"pow_{id(node)}")
        elif isinstance(node.op, ast.BitAnd):
            return left & right
        elif isinstance(node.op, ast.BitOr):
            return left | right
        elif isinstance(node.op, ast.BitXor):
            return left ^ right
        else:
            return z3.Int(f"binop_{id(node)}")

    def visit_Name(self, node: ast.Name) -> z3.ExprRef:
        """Handle variable references."""
        name = node.id
        if name == "result":
            if "__result__" in self.symbols:
                return self.symbols["__result__"]
            return z3.Int("__result__")
        if name.startswith(self._old_prefix):
            actual_name = name[len(self._old_prefix) :]
            old_name = f"old_{actual_name}"
            if old_name in self.symbols:
                return self.symbols[old_name]
        if name in self.symbols:
            return self.symbols[name]
        return z3.Int(name)

    def visit_Constant(self, node: ast.Constant) -> z3.ExprRef:
        """Handle literals."""
        value = node.value
        if isinstance(value, bool):
            return z3.BoolVal(value)
        elif isinstance(value, int):
            return z3.IntVal(value)
        elif isinstance(value, float):
            return z3.RealVal(value)
        else:
            return z3.Int(f"const_{id(node)}")

    def visit_Call(self, node: ast.Call) -> z3.ExprRef:
        """Handle function calls in contracts."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name == "old" and len(node.args) == 1:
                if isinstance(node.args[0], ast.Name):
                    var_name = node.args[0].id
                    old_name = f"old_{var_name}"
                    if old_name in self.symbols:
                        return self.symbols[old_name]
                    return z3.Int(old_name)
            if func_name == "result" and len(node.args) == 0:
                if "__result__" in self.symbols:
                    return self.symbols["__result__"]
                return z3.Int("__result__")
            if func_name == "abs" and len(node.args) == 1:
                arg = self.visit(node.args[0])
                return z3.If(arg >= 0, arg, -arg)
            if func_name == "min" and len(node.args) == 2:
                a, b = self.visit(node.args[0]), self.visit(node.args[1])
                return z3.If(a <= b, a, b)
            if func_name == "max" and len(node.args) == 2:
                a, b = self.visit(node.args[0]), self.visit(node.args[1])
                return z3.If(a >= b, a, b)
            if func_name == "len" and len(node.args) == 1:
                if isinstance(node.args[0], ast.Name):
                    return z3.Int(f"len_{node.args[0].id}")
        return z3.Int(f"call_{id(node)}")

    def visit_IfExp(self, node: ast.IfExp) -> z3.ExprRef:
        """Handle ternary if expressions."""
        test = self.visit(node.test)
        body = self.visit(node.body)
        orelse = self.visit(node.orelse)
        return z3.If(test, body, orelse)

    def visit_Subscript(self, node: ast.Subscript) -> z3.ExprRef:
        """Handle array subscript."""
        if isinstance(node.value, ast.Name):
            base_name = node.value.id
            if isinstance(node.slice, ast.Constant):
                return z3.Int(f"{base_name}_{node.slice.value}")
            elif isinstance(node.slice, ast.Name):
                return z3.Int(f"{base_name}_{node.slice.id}")
        return z3.Int(f"subscript_{id(node)}")

    def generic_visit(self, node: ast.AST) -> z3.ExprRef:
        """Default handler for unknown nodes."""
        return z3.Int(f"unknown_{id(node)}")


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
    ) -> tuple[VerificationResult, dict[str, Any] | None]:
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
    ) -> tuple[VerificationResult, dict[str, Any] | None]:
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
    ) -> tuple[VerificationResult, dict[str, Any] | None]:
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
    ) -> tuple[VerificationResult, dict[str, Any] | None]:
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
    ) -> dict[str, Any]:
        """Extract counterexample values from Z3 model."""
        counterexample = {}
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
            except Exception:
                pass
        return counterexample


_function_contracts: dict[str, FunctionContract] = {}


def get_function_contract(func: Callable) -> FunctionContract | None:
    """Get the contract for a function."""
    key = f"{func.__module__}.{func.__qualname__}"
    return _function_contracts.get(key)


def requires(condition: str, message: str = None):
    """Decorator to add a precondition to a function.
    Example:
        @requires("x > 0", "x must be positive")
        @requires("y != 0", "y must be non-zero")
        def divide(x, y):
            return x / y
    """

    def decorator(func: Callable) -> Callable:
        key = f"{func.__module__}.{func.__qualname__}"
        if key not in _function_contracts:
            _function_contracts[key] = FunctionContract(function_name=func.__name__)
        contract = _function_contracts[key]
        try:
            source_lines = inspect.getsourcelines(func)
            line_num = source_lines[1]
        except Exception:
            line_num = None
        contract.add_precondition(condition, message, line_num)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        wrapper.__contract__ = contract
        return wrapper

    return decorator


def ensures(condition: str, message: str = None):
    """Decorator to add a postcondition to a function.
    Use 'result()' to refer to the return value.
    Use 'old(x)' to refer to the value of x before the function.
    Example:
        @ensures("result() >= 0", "result must be non-negative")
        @ensures("result() == old(x) + old(y)", "result is sum of inputs")
        def add(x, y):
            return x + y
    """

    def decorator(func: Callable) -> Callable:
        key = f"{func.__module__}.{func.__qualname__}"
        if key not in _function_contracts:
            _function_contracts[key] = FunctionContract(function_name=func.__name__)
        contract = _function_contracts[key]
        try:
            source_lines = inspect.getsourcelines(func)
            line_num = source_lines[1]
        except Exception:
            line_num = None
        contract.add_postcondition(condition, message, line_num)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        wrapper.__contract__ = contract
        return wrapper

    return decorator


def invariant(condition: str, message: str = None):
    """Decorator to add a class invariant.
    The invariant must hold after __init__ and after every public method.
    Example:
        @invariant("self.balance >= 0", "balance must be non-negative")
        class BankAccount:
            def __init__(self, initial):
                self.balance = initial
    """

    def decorator(cls: type) -> type:
        if not hasattr(cls, "__invariants__"):
            cls.__invariants__ = []
        cls.__invariants__.append(
            Contract(
                kind=ContractKind.INVARIANT,
                condition=condition,
                message=message or f"Invariant: {condition}",
            )
        )
        return cls

    return decorator


def loop_invariant(condition: str, message: str = None):
    """Marker for loop invariants (used in comments or type hints).
    Example:
        def sum_list(lst):
            total = 0
            i = 0
            # loop_invariant: total == sum(lst[:i])
            while i < len(lst):
                total += lst[i]
                i += 1
            return total
    """
    return Contract(
        kind=ContractKind.LOOP_INVARIANT,
        condition=condition,
        message=message or f"Loop invariant: {condition}",
    )


@dataclass
class VerificationReport:
    """Report of contract verification results."""

    function_name: str
    total_contracts: int = 0
    verified: int = 0
    violated: int = 0
    unknown: int = 0
    violations: list[ContractViolation] = field(default_factory=list)

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
        counterexample: dict[str, Any] | None = None,
        function_name: str = None,
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
            f"Verification Report: {self.function_name}",
            "=" * 50,
            f"Total contracts: {self.total_contracts}",
            f"  Verified: {self.verified}",
            f"  Violated: {self.violated}",
            f"  Unknown:  {self.unknown}",
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
    Integrates with PySpectre's symbolic execution engine to verify
    that contracts hold for all possible inputs.
    """

    def __init__(self, verifier: ContractVerifier | None = None):
        self.verifier = verifier or ContractVerifier()
        self._reports: dict[str, VerificationReport] = {}

    def analyze_function(
        self,
        func: Callable,
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
            return report
        symbols = self._build_symbols(func, symbolic_args or {})
        for pre in contract.preconditions:
            result, counter = self.verifier.verify_precondition(pre, [], symbols)
            report.add_result(pre, result, counter, func.__name__)
        for post in contract.postconditions:
            symbols_with_old = dict(symbols)
            for name, expr in symbols.items():
                old_name = f"old_{name}"
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
        self._reports[func.__name__] = report
        return report

    def _build_symbols(
        self,
        func: Callable,
        symbolic_args: dict[str, str],
    ) -> dict[str, z3.ExprRef]:
        """Build symbolic variables for function arguments."""
        symbols = {}
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
        except Exception:
            pass
        return symbols

    def get_report(self, func_name: str) -> VerificationReport | None:
        """Get the verification report for a function."""
        return self._reports.get(func_name)

    def get_all_reports(self) -> list[VerificationReport]:
        """Get all verification reports."""
        return list(self._reports.values())


__all__ = [
    "ContractKind",
    "VerificationResult",
    "ContractViolation",
    "Contract",
    "FunctionContract",
    "ContractCompiler",
    "ContractVerifier",
    "requires",
    "ensures",
    "invariant",
    "loop_invariant",
    "get_function_contract",
    "VerificationReport",
    "ContractAnalyzer",
]
