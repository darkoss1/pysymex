"""Advanced Arithmetic Safety Analysis with Z3.
This module provides comprehensive arithmetic safety checking using Z3 SMT solver
for mathematical proofs of correctness. Covers:
- Integer overflow/underflow detection
- Floating-point safety (NaN, Inf, precision loss)
- Division safety (division by zero, modulo)
- Bitwise operation safety
- Wrapping vs saturating arithmetic
- Arbitrary precision integer bounds
"""

from __future__ import annotations

import icontract
import logging

logger = logging.getLogger(__name__)

from dataclasses import dataclass, field
from enum import Enum, auto

import z3

from pysymex.core.solver import get_model, is_satisfiable


class ArithmeticMode(Enum):
    """How arithmetic operations handle overflow."""

    WRAPPING = auto()
    SATURATING = auto()
    CHECKED = auto()
    ARBITRARY = auto()


class IntegerWidth(Enum):
    """Standard integer bit widths."""

    INT8 = 8
    INT16 = 16
    INT32 = 32
    INT64 = 64
    INT128 = 128
    ARBITRARY = 0


@dataclass
class IntegerBounds:
    """Bounds for an integer type."""

    width: IntegerWidth
    signed: bool
    min_val: int
    max_val: int

    @classmethod
    @icontract.ensure(lambda result: result.min_val <= result.max_val)
    def for_width(cls, width: IntegerWidth, signed: bool = True) -> IntegerBounds:
        """Create bounds for a specific bit width."""
        if width == IntegerWidth.ARBITRARY:
            return cls(width, signed, -(2**256), 2**256 - 1)
        bits = width.value
        if signed:
            return cls(width, signed, -(2 ** (bits - 1)), 2 ** (bits - 1) - 1)
        else:
            return cls(width, signed, 0, 2**bits - 1)

    def contains(self, value: int) -> bool:
        """Check if value is within bounds."""
        return self.min_val <= value <= self.max_val

    def to_z3_constraints(self, var: z3.ArithRef) -> list[z3.BoolRef]:
        """Generate Z3 constraints for these bounds."""
        return [var >= self.min_val, var <= self.max_val]


class ArithmeticIssueKind(Enum):
    """Types of arithmetic safety issues."""

    SIGNED_OVERFLOW = auto()
    SIGNED_UNDERFLOW = auto()
    UNSIGNED_OVERFLOW = auto()
    UNSIGNED_UNDERFLOW = auto()
    DIVISION_BY_ZERO = auto()
    MODULO_BY_ZERO = auto()
    DIVISION_OVERFLOW = auto()
    FLOAT_NAN = auto()
    FLOAT_INFINITY = auto()
    FLOAT_PRECISION_LOSS = auto()
    FLOAT_DENORMAL = auto()
    SHIFT_OVERFLOW = auto()
    NEGATIVE_SHIFT = auto()
    TRUNCATION = auto()
    SIGN_LOSS = auto()
    POWER_OVERFLOW = auto()
    ABS_OVERFLOW = auto()


@dataclass
class ArithmeticIssue:
    """Represents a detected arithmetic safety issue."""

    kind: ArithmeticIssueKind
    message: str
    location: str | None = None
    line_number: int | None = None
    constraints: list[object] = field(default_factory=list[object])
    counterexample: dict[str, object] = field(default_factory=dict[str, object])
    severity: str = "error"

    def format(self) -> str:
        """Format issue for display."""
        loc = f" at line {self .line_number }" if self.line_number else ""
        ce = ""
        if self.counterexample:
            ce = " | Counterexample: " + ", ".join(
                f"{k }={v }" for k, v in self.counterexample.items()
            )
        return f"[{self .kind .name }]{loc }: {self .message }{ce }"


class ArithmeticSafetyAnalyzer:
    """
    Comprehensive arithmetic safety analyzer using Z3.
    Provides mathematically proven detection of arithmetic issues
    across multiple integer widths and modes.
    """

    def __init__(
        self,
        mode: ArithmeticMode = ArithmeticMode.CHECKED,
        default_width: IntegerWidth = IntegerWidth.INT64,
        signed: bool = True,
        timeout_ms: int = 5000,
    ):
        self.mode = mode
        self.default_width = default_width
        self.signed = signed
        self.timeout_ms = timeout_ms
        self.bounds = IntegerBounds.for_width(default_width, signed)
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)
        self._issues: list[ArithmeticIssue] = []

    def reset(self) -> None:
        """Reset analyzer state."""
        self._solver.reset()
        self._issues.clear()

    @icontract.ensure(lambda result: result is None or isinstance(result, ArithmeticIssue))
    def check_addition_overflow(
        self,
        a: z3.ExprRef,
        b: z3.ExprRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ArithmeticIssue | None:
        """
        Check if a + b can overflow.
        For signed integers:
        - Overflow: a > 0 AND b > 0 AND a + b < 0
        - Underflow: a < 0 AND b < 0 AND a + b > 0
        """
        constraints = list(path_constraints or [])
        result = a + b
        if self.signed:
            overflow_cond = z3.And(a > 0, b > 0, result > self.bounds.max_val)
            underflow_cond = z3.And(a < 0, b < 0, result < self.bounds.min_val)
            if is_satisfiable(constraints + [overflow_cond]):
                model = get_model(constraints + [overflow_cond])
                return ArithmeticIssue(
                    kind=ArithmeticIssueKind.SIGNED_OVERFLOW,
                    message=f"Addition overflow: {a } + {b } exceeds {self .bounds .max_val }",
                    constraints=constraints + [overflow_cond],
                    counterexample=self._extract_model(model, [a, b]),
                )
            if is_satisfiable(constraints + [underflow_cond]):
                model = get_model(constraints + [underflow_cond])
                return ArithmeticIssue(
                    kind=ArithmeticIssueKind.SIGNED_UNDERFLOW,
                    message=f"Addition underflow: {a } + {b } below {self .bounds .min_val }",
                    constraints=constraints + [underflow_cond],
                    counterexample=self._extract_model(model, [a, b]),
                )
        else:
            overflow_cond = result > self.bounds.max_val
            if is_satisfiable(constraints + [overflow_cond]):
                model = get_model(constraints + [overflow_cond])
                return ArithmeticIssue(
                    kind=ArithmeticIssueKind.UNSIGNED_OVERFLOW,
                    message="Unsigned addition overflow",
                    constraints=constraints + [overflow_cond],
                    counterexample=self._extract_model(model, [a, b]),
                )
        return None

    def check_subtraction_overflow(
        self,
        a: z3.ExprRef,
        b: z3.ExprRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ArithmeticIssue | None:
        """Check if a - b can overflow/underflow."""
        constraints = list(path_constraints or [])
        result = a - b
        if self.signed:
            overflow_cond = z3.And(a > 0, b < 0, result > self.bounds.max_val)
            underflow_cond = z3.And(a < 0, b > 0, result < self.bounds.min_val)
            if is_satisfiable(constraints + [overflow_cond]):
                model = get_model(constraints + [overflow_cond])
                return ArithmeticIssue(
                    kind=ArithmeticIssueKind.SIGNED_OVERFLOW,
                    message=f"Subtraction overflow: {a } - {b }",
                    constraints=constraints + [overflow_cond],
                    counterexample=self._extract_model(model, [a, b]),
                )
            if is_satisfiable(constraints + [underflow_cond]):
                model = get_model(constraints + [underflow_cond])
                return ArithmeticIssue(
                    kind=ArithmeticIssueKind.SIGNED_UNDERFLOW,
                    message=f"Subtraction underflow: {a } - {b }",
                    constraints=constraints + [underflow_cond],
                    counterexample=self._extract_model(model, [a, b]),
                )
        else:
            underflow_cond = a < b
            if is_satisfiable(constraints + [underflow_cond]):
                model = get_model(constraints + [underflow_cond])
                return ArithmeticIssue(
                    kind=ArithmeticIssueKind.UNSIGNED_UNDERFLOW,
                    message="Unsigned subtraction underflow",
                    constraints=constraints + [underflow_cond],
                    counterexample=self._extract_model(model, [a, b]),
                )
        return None

    def check_multiplication_overflow(
        self,
        a: z3.ExprRef,
        b: z3.ExprRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ArithmeticIssue | None:
        """Check if a * b can overflow."""
        constraints = list(path_constraints or [])
        result = a * b
        overflow_cond = z3.Or(result > self.bounds.max_val, result < self.bounds.min_val)
        if is_satisfiable(constraints + [overflow_cond]):
            model = get_model(constraints + [overflow_cond])
            return ArithmeticIssue(
                kind=(
                    ArithmeticIssueKind.SIGNED_OVERFLOW
                    if self.signed
                    else ArithmeticIssueKind.UNSIGNED_OVERFLOW
                ),
                message=f"Multiplication overflow: {a } * {b }",
                constraints=constraints + [overflow_cond],
                counterexample=self._extract_model(model, [a, b]),
            )
        return None

    def check_division_safety(
        self,
        a: z3.ExprRef,
        b: z3.ExprRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[ArithmeticIssue]:
        """
        Comprehensive division safety check.
        Checks:
        1. Division by zero
        2. INT_MIN / -1 overflow (for signed)
        """
        issues: list[ArithmeticIssue] = []
        constraints = list(path_constraints or [])
        div_zero_cond = b == 0
        if is_satisfiable(constraints + [div_zero_cond]):
            model = get_model(constraints + [div_zero_cond])
            issues.append(
                ArithmeticIssue(
                    kind=ArithmeticIssueKind.DIVISION_BY_ZERO,
                    message="Division by zero possible",
                    constraints=constraints + [div_zero_cond],
                    counterexample=self._extract_model(model, [a, b]),
                )
            )
        if self.signed and self.default_width != IntegerWidth.ARBITRARY:
            int_min = self.bounds.min_val
            overflow_cond = z3.And(a == int_min, b == -1)
            if is_satisfiable(constraints + [overflow_cond]):
                model = get_model(constraints + [overflow_cond])
                issues.append(
                    ArithmeticIssue(
                        kind=ArithmeticIssueKind.DIVISION_OVERFLOW,
                        message=f"Division overflow: {int_min } / -1",
                        constraints=constraints + [overflow_cond],
                        counterexample=self._extract_model(model, [a, b]),
                    )
                )
        return issues

    @icontract.ensure(lambda result: result is None or isinstance(result, ArithmeticIssue))
    def check_modulo_safety(
        self,
        a: z3.ExprRef,
        b: z3.ExprRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ArithmeticIssue | None:
        """Check if a % b is safe (b != 0)."""
        constraints = list(path_constraints or [])
        mod_zero_cond = b == 0
        if is_satisfiable(constraints + [mod_zero_cond]):
            model = get_model(constraints + [mod_zero_cond])
            return ArithmeticIssue(
                kind=ArithmeticIssueKind.MODULO_BY_ZERO,
                message="Modulo by zero possible",
                constraints=constraints + [mod_zero_cond],
                counterexample=self._extract_model(model, [a, b]),
            )
        return None

    def check_shift_safety(
        self,
        value: z3.ArithRef,
        shift_amount: z3.ArithRef,
        _is_left_shift: bool = True,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[ArithmeticIssue]:
        """
        Check shift operation safety.
        Issues:
        1. Shift by negative amount
        2. Shift by >= bit width
        """
        issues: list[ArithmeticIssue] = []
        constraints = list(path_constraints or [])
        bit_width = self.default_width.value if self.default_width != IntegerWidth.ARBITRARY else 64
        neg_shift_cond = shift_amount < 0
        if is_satisfiable(constraints + [neg_shift_cond]):
            model = get_model(constraints + [neg_shift_cond])
            issues.append(
                ArithmeticIssue(
                    kind=ArithmeticIssueKind.NEGATIVE_SHIFT,
                    message="Shift by negative amount",
                    constraints=constraints + [neg_shift_cond],
                    counterexample=self._extract_model(model, [value, shift_amount]),
                )
            )
        overflow_cond = shift_amount >= bit_width
        if is_satisfiable(constraints + [overflow_cond]):
            model = get_model(constraints + [overflow_cond])
            issues.append(
                ArithmeticIssue(
                    kind=ArithmeticIssueKind.SHIFT_OVERFLOW,
                    message=f"Shift amount >= {bit_width } bits",
                    constraints=constraints + [overflow_cond],
                    counterexample=self._extract_model(model, [value, shift_amount]),
                )
            )
        return issues

    def check_power_safety(
        self,
        base: z3.ExprRef,
        exponent: z3.ExprRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[ArithmeticIssue]:
        """
        Check power operation safety (base ** exponent).
        Issues:
        1. Overflow for large results
        2. 0 ** negative (undefined/infinity)
        """
        issues: list[ArithmeticIssue] = []
        constraints = list(path_constraints or [])
        zero_neg_cond = z3.And(base == 0, exponent < 0)
        if is_satisfiable(constraints + [zero_neg_cond]):
            model = get_model(constraints + [zero_neg_cond])
            issues.append(
                ArithmeticIssue(
                    kind=ArithmeticIssueKind.DIVISION_BY_ZERO,
                    message="0 raised to negative power (division by zero)",
                    constraints=constraints + [zero_neg_cond],
                    counterexample=self._extract_model(model, [base, exponent]),
                )
            )
        if self.default_width != IntegerWidth.ARBITRARY:
            overflow_cond = z3.And(z3.Or(base > 1, base < -1), exponent > self.default_width.value)
            if is_satisfiable(constraints + [overflow_cond]):
                model = get_model(constraints + [overflow_cond])
                issues.append(
                    ArithmeticIssue(
                        kind=ArithmeticIssueKind.POWER_OVERFLOW,
                        message="Power operation may overflow",
                        constraints=constraints + [overflow_cond],
                        counterexample=self._extract_model(model, [base, exponent]),
                    )
                )
        return issues

    def check_abs_safety(
        self,
        value: z3.ArithRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ArithmeticIssue | None:
        """
        Check abs() safety.
        For signed integers, abs(INT_MIN) overflows because
        -INT_MIN cannot be represented.
        """
        if not self.signed or self.default_width == IntegerWidth.ARBITRARY:
            return None
        constraints = list(path_constraints or [])
        int_min = self.bounds.min_val
        overflow_cond = value == int_min
        if is_satisfiable(constraints + [overflow_cond]):
            model = get_model(constraints + [overflow_cond])
            return ArithmeticIssue(
                kind=ArithmeticIssueKind.ABS_OVERFLOW,
                message=f"abs({int_min }) overflows",
                constraints=constraints + [overflow_cond],
                counterexample=self._extract_model(model, [value]),
            )
        return None

    def check_narrowing_conversion(
        self,
        value: z3.ArithRef,
        target_width: IntegerWidth,
        target_signed: bool = True,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[ArithmeticIssue]:
        """
        Check if narrowing conversion is safe.
        E.g., converting int64 to int32 may truncate.
        """
        issues: list[ArithmeticIssue] = []
        constraints = list(path_constraints or [])
        target_bounds = IntegerBounds.for_width(target_width, target_signed)
        too_large = value > target_bounds.max_val
        if is_satisfiable(constraints + [too_large]):
            model = get_model(constraints + [too_large])
            issues.append(
                ArithmeticIssue(
                    kind=ArithmeticIssueKind.TRUNCATION,
                    message=f"Value exceeds {target_width .name } max ({target_bounds .max_val })",
                    constraints=constraints + [too_large],
                    counterexample=self._extract_model(model, [value]),
                )
            )
        too_small = value < target_bounds.min_val
        if is_satisfiable(constraints + [too_small]):
            model = get_model(constraints + [too_small])
            issues.append(
                ArithmeticIssue(
                    kind=ArithmeticIssueKind.TRUNCATION,
                    message=f"Value below {target_width .name } min ({target_bounds .min_val })",
                    constraints=constraints + [too_small],
                    counterexample=self._extract_model(model, [value]),
                )
            )
        if self.signed and not target_signed:
            sign_loss = value < 0
            if is_satisfiable(constraints + [sign_loss]):
                model = get_model(constraints + [sign_loss])
                issues.append(
                    ArithmeticIssue(
                        kind=ArithmeticIssueKind.SIGN_LOSS,
                        message="Negative value converted to unsigned",
                        constraints=constraints + [sign_loss],
                        counterexample=self._extract_model(model, [value]),
                    )
                )
        return issues

    def check_float_division_safety(
        self,
        a: z3.RealRef,
        b: z3.RealRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[ArithmeticIssue]:
        """Check floating-point division safety."""
        issues: list[ArithmeticIssue] = []
        constraints = list(path_constraints or [])
        div_zero = b == 0
        if is_satisfiable(constraints + [div_zero]):
            model = get_model(constraints + [div_zero])
            issues.append(
                ArithmeticIssue(
                    kind=ArithmeticIssueKind.FLOAT_INFINITY,
                    message="Float division by zero produces infinity",
                    constraints=constraints + [div_zero],
                    counterexample=self._extract_model(model, [a, b]),
                )
            )
        nan_cond = z3.And(a == 0, b == 0)
        if is_satisfiable(constraints + [nan_cond]):
            model = get_model(constraints + [nan_cond])
            issues.append(
                ArithmeticIssue(
                    kind=ArithmeticIssueKind.FLOAT_NAN,
                    message="0.0 / 0.0 produces NaN",
                    constraints=constraints + [nan_cond],
                    counterexample=self._extract_model(model, [a, b]),
                )
            )
        return issues

    def analyze_expression(
        self,
        expr: z3.ExprRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[ArithmeticIssue]:
        """
        Recursively analyze an expression for all arithmetic issues.
        """
        issues: list[ArithmeticIssue] = []

        def visit(e: z3.ExprRef) -> None:
            if z3.is_app(e):
                decl = e.decl()
                kind = decl.kind()
                args = [e.arg(i) for i in range(e.num_args())]
                if kind == z3.Z3_OP_ADD and len(args) == 2:
                    issue = self.check_addition_overflow(args[0], args[1], path_constraints)
                    if issue:
                        issues.append(issue)
                elif kind == z3.Z3_OP_SUB and len(args) == 2:
                    issue = self.check_subtraction_overflow(args[0], args[1], path_constraints)
                    if issue:
                        issues.append(issue)
                elif kind == z3.Z3_OP_MUL and len(args) == 2:
                    issue = self.check_multiplication_overflow(args[0], args[1], path_constraints)
                    if issue:
                        issues.append(issue)
                elif (kind == z3.Z3_OP_DIV and len(args) == 2) or (
                    kind == z3.Z3_OP_IDIV and len(args) == 2
                ):
                    issues.extend(self.check_division_safety(args[0], args[1], path_constraints))
                elif kind == z3.Z3_OP_MOD and len(args) == 2:
                    issue = self.check_modulo_safety(args[0], args[1], path_constraints)
                    if issue:
                        issues.append(issue)
                elif kind == z3.Z3_OP_POWER and len(args) == 2:
                    issues.extend(self.check_power_safety(args[0], args[1], path_constraints))
                for arg in args:
                    visit(arg)

        visit(expr)
        return issues

    def _extract_model(
        self,
        model: z3.ModelRef | None,
        variables: list[z3.ExprRef],
    ) -> dict[str, object]:
        """Extract variable values from Z3 model."""
        if model is None:
            return {}
        result: dict[str, object] = {}
        for var in variables:
            try:
                val = model.eval(var, model_completion=True)
                if z3.is_int_value(val):
                    result[str(var)] = val.as_long()
                elif z3.is_rational_value(val):
                    result[str(var)] = float(val.as_fraction())
                else:
                    result[str(var)] = str(val)
            except z3.Z3Exception:
                logger.error("Z3Exception during model evaluation in SafeArithmetic", exc_info=True)
        return result


class SafeArithmetic:
    """
    Provides arithmetic operations that are proven safe via Z3.
    Each operation returns (result, is_safe, issue) tuple.
    """

    def __init__(self, analyzer: ArithmeticSafetyAnalyzer | None = None):
        self.analyzer = analyzer or ArithmeticSafetyAnalyzer()

    @icontract.ensure(lambda result: isinstance(result[0], z3.ArithRef))
    def safe_add(
        self,
        a: z3.ArithRef,
        b: z3.ArithRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[z3.ArithRef, bool, ArithmeticIssue | None]:
        """Add with safety check."""
        issue = self.analyzer.check_addition_overflow(a, b, constraints)
        return (a + b, issue is None, issue)

    def safe_sub(
        self,
        a: z3.ArithRef,
        b: z3.ArithRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[z3.ArithRef, bool, ArithmeticIssue | None]:
        """Subtract with safety check."""
        issue = self.analyzer.check_subtraction_overflow(a, b, constraints)
        return (a - b, issue is None, issue)

    def safe_mul(
        self,
        a: z3.ArithRef,
        b: z3.ArithRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[z3.ArithRef, bool, ArithmeticIssue | None]:
        """Multiply with safety check."""
        issue = self.analyzer.check_multiplication_overflow(a, b, constraints)
        return (a * b, issue is None, issue)

    def safe_div(
        self,
        a: z3.ArithRef,
        b: z3.ArithRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[z3.ArithRef, bool, list[ArithmeticIssue]]:
        """Divide with safety check."""
        issues = self.analyzer.check_division_safety(a, b, constraints)
        result = z3.If(b != 0, a / b, z3.IntVal(0))
        return (result, len(issues) == 0, issues)


__all__ = [
    "ArithmeticIssue",
    "ArithmeticIssueKind",
    "ArithmeticMode",
    "ArithmeticSafetyAnalyzer",
    "IntegerBounds",
    "IntegerWidth",
    "SafeArithmetic",
]
