"""Property-based verification logic for pysymex.

Contains the core prover/verifier/checker classes:
- PropertyProver: Proves mathematical properties using Z3
- ArithmeticVerifier: Verifies arithmetic properties and detects potential issues
- EquivalenceChecker: Proves equivalence between different implementations
"""

from __future__ import annotations


import logging

from collections.abc import Callable

from typing import Any


import z3


from pysymex.analysis.properties.types import (
    PropertyKind,
    PropertyProof,
    PropertySpec,
    ProofStatus,
)

logger = logging.getLogger(__name__)


class PropertyProver:
    """Proves mathematical properties using Z3.
    Supports:
    - Algebraic property verification
    - Bound checking
    - Monotonicity proofs
    - Equivalence checking
    """

    def __init__(self, timeout_ms: int = 10000):
        self.timeout_ms = timeout_ms

        self._solver = z3.Solver()

        self._solver.set("timeout", timeout_ms)

    def prove_commutativity(
        self,
        f: Callable[[z3.ExprRef, z3.ExprRef], z3.ExprRef],
        a: z3.ExprRef,
        b: z3.ExprRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove f(a, b) == f(b, a) for all a, b."""

        spec = PropertySpec(
            kind=PropertyKind.COMMUTATIVITY,
            name="Commutativity",
            description="f(a, b) == f(b, a)",
            constraints=constraints or [],
        )

        self._solver.reset()

        for c in constraints or []:
            self._solver.add(c)

        lhs = f(a, b)

        rhs = f(b, a)

        self._solver.add(lhs != rhs)

        return self._check_proof(spec, {"a": a, "b": b})

    def prove_associativity(
        self,
        f: Callable[[z3.ExprRef, z3.ExprRef], z3.ExprRef],
        a: z3.ExprRef,
        b: z3.ExprRef,
        c: z3.ExprRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove f(f(a, b), c) == f(a, f(b, c)) for all a, b, c."""

        spec = PropertySpec(
            kind=PropertyKind.ASSOCIATIVITY,
            name="Associativity",
            description="f(f(a, b), c) == f(a, f(b, c))",
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        lhs = f(f(a, b), c)

        rhs = f(a, f(b, c))

        self._solver.add(lhs != rhs)

        return self._check_proof(spec, {"a": a, "b": b, "c": c})

    def prove_identity(
        self,
        f: Callable[[z3.ExprRef, z3.ExprRef], z3.ExprRef],
        a: z3.ExprRef,
        identity: z3.ExprRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove f(a, identity) == a for all a."""

        spec = PropertySpec(
            kind=PropertyKind.IDENTITY,
            name="Identity",
            description=f"f(a, {identity}) == a",
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        result = f(a, identity)

        self._solver.add(result != a)

        return self._check_proof(spec, {"a": a})

    def prove_idempotence(
        self,
        f: Callable[[z3.ExprRef, z3.ExprRef], z3.ExprRef],
        a: z3.ExprRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove f(a, a) == a for all a."""

        spec = PropertySpec(
            kind=PropertyKind.IDEMPOTENCE,
            name="Idempotence",
            description="f(a, a) == a",
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        result = f(a, a)

        self._solver.add(result != a)

        return self._check_proof(spec, {"a": a})

    def prove_monotonic_increasing(
        self,
        f: Callable[[z3.ExprRef], z3.ExprRef],
        x: z3.ExprRef,
        y: z3.ExprRef,
        constraints: list[z3.BoolRef] | None = None,
        strict: bool = False,
    ) -> PropertyProof:
        """Prove x <= y => f(x) <= f(y) (or strict: x < y => f(x) < f(y))."""

        kind = PropertyKind.STRICT_MONOTONIC_INC if strict else PropertyKind.MONOTONIC_INC

        op = "<" if strict else "<="

        spec = PropertySpec(
            kind=kind,
            name=f"Monotonically Increasing ({op})",
            description=f"x {op} y => f(x) {op} f(y)",
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        if strict:
            self._solver.add(x < y)

            self._solver.add(z3.Not(f(x) < f(y)))

        else:
            self._solver.add(x <= y)

            self._solver.add(z3.Not(f(x) <= f(y)))

        return self._check_proof(spec, {"x": x, "y": y})

    def prove_monotonic_decreasing(
        self,
        f: Callable[[z3.ExprRef], z3.ExprRef],
        x: z3.ExprRef,
        y: z3.ExprRef,
        constraints: list[z3.BoolRef] | None = None,
        strict: bool = False,
    ) -> PropertyProof:
        """Prove x <= y => f(x) >= f(y)."""

        kind = PropertyKind.STRICT_MONOTONIC_DEC if strict else PropertyKind.MONOTONIC_DEC

        spec = PropertySpec(
            kind=kind,
            name="Monotonically Decreasing",
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        if strict:
            self._solver.add(x < y)

            self._solver.add(z3.Not(f(x) > f(y)))

        else:
            self._solver.add(x <= y)

            self._solver.add(z3.Not(f(x) >= f(y)))

        return self._check_proof(spec, {"x": x, "y": y})

    def prove_lower_bound(
        self,
        expr: z3.ExprRef,
        bound: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove expr >= bound for all inputs."""

        spec = PropertySpec(
            kind=PropertyKind.LOWER_BOUND,
            name=f"Lower Bound ({bound})",
            description=f"expr >= {bound}",
            constraints=constraints or [],
            lower_bound=bound,
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(expr < bound)

        return self._check_proof(spec, variables)

    def prove_upper_bound(
        self,
        expr: z3.ExprRef,
        bound: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove expr <= bound for all inputs."""

        spec = PropertySpec(
            kind=PropertyKind.UPPER_BOUND,
            name=f"Upper Bound ({bound})",
            description=f"expr <= {bound}",
            constraints=constraints or [],
            upper_bound=bound,
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(expr > bound)

        return self._check_proof(spec, variables)

    def prove_bounded(
        self,
        expr: z3.ExprRef,
        lower: z3.ExprRef,
        upper: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove lower <= expr <= upper for all inputs."""

        spec = PropertySpec(
            kind=PropertyKind.BOUNDED,
            name=f"Bounded [{lower}, {upper}]",
            description=f"{lower} <= expr <= {upper}",
            constraints=constraints or [],
            lower_bound=lower,
            upper_bound=upper,
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(z3.Or(expr < lower, expr > upper))

        return self._check_proof(spec, variables)

    def prove_non_negative(
        self,
        expr: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove expr >= 0 for all inputs."""

        return self.prove_lower_bound(expr, z3.IntVal(0), variables, constraints)

    def prove_positive(
        self,
        expr: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove expr > 0 for all inputs."""

        spec = PropertySpec(
            kind=PropertyKind.POSITIVE,
            name="Positive",
            description="expr > 0",
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(expr <= 0)

        return self._check_proof(spec, variables)

    def prove_equivalence(
        self,
        expr1: z3.ExprRef,
        expr2: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove expr1 == expr2 for all inputs."""

        spec = PropertySpec(
            kind=PropertyKind.EQUIVALENCE,
            name="Equivalence",
            description="expr1 == expr2",
            constraints=constraints or [],
            equivalent_expr=expr2,
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(expr1 != expr2)

        return self._check_proof(spec, variables)

    def prove_even_function(
        self,
        f: Callable[[z3.ExprRef], z3.ExprRef],
        x: z3.ExprRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove f(-x) == f(x) for all x."""

        spec = PropertySpec(
            kind=PropertyKind.EVEN_FUNCTION,
            name="Even Function",
            description="f(-x) == f(x)",
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(f(-x) != f(x))

        return self._check_proof(spec, {"x": x})

    def prove_odd_function(
        self,
        f: Callable[[z3.ExprRef], z3.ExprRef],
        x: z3.ExprRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove f(-x) == -f(x) for all x."""

        spec = PropertySpec(
            kind=PropertyKind.ODD_FUNCTION,
            name="Odd Function",
            description="f(-x) == -f(x)",
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(f(-x) != -f(x))

        return self._check_proof(spec, {"x": x})

    def prove_injective(
        self,
        f: Callable[[z3.ExprRef], z3.ExprRef],
        x: z3.ExprRef,
        y: z3.ExprRef,
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Prove f(x) == f(y) => x == y (one-to-one)."""

        spec = PropertySpec(
            kind=PropertyKind.INJECTIVE,
            name="Injective (One-to-One)",
            description="f(x) == f(y) => x == y",
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(f(x) == f(y))

        self._solver.add(x != y)

        return self._check_proof(spec, {"x": x, "y": y})

    def prove_custom(
        self,
        name: str,
        property_expr: z3.BoolRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
        description: str = "",
    ) -> PropertyProof:
        """Prove a custom property expression."""

        spec = PropertySpec(
            kind=PropertyKind.EQUIVALENCE,
            name=name,
            description=description,
            constraints=constraints or [],
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(z3.Not(property_expr))

        return self._check_proof(spec, variables)

    def _check_proof(
        self,
        spec: PropertySpec,
        variables: dict[str, z3.ExprRef],
    ) -> PropertyProof:
        """Check solver and construct proof result."""

        import time

        start = time.time()

        result = self._solver.check()

        elapsed = time.time() - start

        if result == z3.unsat:
            return PropertyProof(
                property=spec,
                status=ProofStatus.PROVEN,
                time_seconds=elapsed,
            )

        elif result == z3.sat:
            model = self._solver.model()

            counterexample = self._extract_model(model, variables)

            return PropertyProof(
                property=spec,
                status=ProofStatus.DISPROVEN,
                counterexample=counterexample,
                time_seconds=elapsed,
            )

        else:
            return PropertyProof(
                property=spec,
                status=(
                    ProofStatus.TIMEOUT if elapsed > self.timeout_ms / 1000 else ProofStatus.UNKNOWN
                ),
                time_seconds=elapsed,
            )

    def _extract_model(
        self,
        model: z3.ModelRef,
        variables: dict[str, z3.ExprRef],
    ) -> dict[str, Any]:
        """Extract values from Z3 model."""

        result: dict[str, Any] = {}

        for name, expr in variables.items():
            try:
                val = model.eval(expr, model_completion=True)

                if z3.is_int_value(val):
                    result[name] = val.as_long()

                elif z3.is_rational_value(val):
                    result[name] = float(val.as_fraction())

                elif z3.is_true(val):
                    result[name] = True

                elif z3.is_false(val):
                    result[name] = False

                else:
                    result[name] = str(val)

            except Exception:
                logger.debug("Model eval failed for variable %s", name, exc_info=True)

        return result


class ArithmeticVerifier:
    """Verifies arithmetic properties and detects potential issues.
    Checks for:
    - Integer overflow/underflow
    - Division by zero
    - Precision loss in float operations
    - Numeric bounds violations
    """

    def __init__(self, int_bits: int = 64, timeout_ms: int = 5000):
        self.int_bits = int_bits

        self.int_min = -(2 ** (int_bits - 1))

        self.int_max = 2 ** (int_bits - 1) - 1

        self.timeout_ms = timeout_ms

        self._solver = z3.Solver()

        self._solver.set("timeout", timeout_ms)

    def check_overflow(
        self,
        expr: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if expression can overflow."""

        spec = PropertySpec(
            kind=PropertyKind.BOUNDED,
            name="No Overflow",
            description=f"Result within [{self.int_min}, {self.int_max}]",
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(z3.Or(expr < self.int_min, expr > self.int_max))

        result = self._solver.check()

        if result == z3.unsat:
            return PropertyProof(property=spec, status=ProofStatus.PROVEN)

        elif result == z3.sat:
            model = self._solver.model()

            counterexample: dict[str, Any] = {}

            for name, var in variables.items():
                try:
                    val = model.eval(var, model_completion=True)

                    counterexample[name] = val.as_long() if z3.is_int_value(val) else str(val)

                except Exception:
                    logger.debug("Model eval failed in check_overflow for %s", name, exc_info=True)

            return PropertyProof(
                property=spec,
                status=ProofStatus.DISPROVEN,
                counterexample=counterexample,
            )

        else:
            return PropertyProof(property=spec, status=ProofStatus.UNKNOWN)

    def check_underflow(
        self,
        expr: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if expression can underflow (go below minimum)."""

        return self.check_overflow(expr, variables, constraints)

    def check_division_safe(
        self,
        dividend: z3.ExprRef,
        divisor: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if division is safe (divisor != 0)."""

        spec = PropertySpec(
            kind=PropertyKind.POSITIVE,
            name="Division Safety",
            description="divisor != 0",
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(divisor == 0)

        result = self._solver.check()

        if result == z3.unsat:
            return PropertyProof(property=spec, status=ProofStatus.PROVEN)

        elif result == z3.sat:
            model = self._solver.model()

            counterexample: dict[str, Any] = {}

            for name, var in variables.items():
                try:
                    val = model.eval(var, model_completion=True)

                    counterexample[name] = val.as_long() if z3.is_int_value(val) else str(val)

                except Exception:
                    logger.debug(
                        "Model eval failed in check_division_by_zero for %s", name, exc_info=True
                    )

            return PropertyProof(
                property=spec,
                status=ProofStatus.DISPROVEN,
                counterexample=counterexample,
            )

        else:
            return PropertyProof(property=spec, status=ProofStatus.UNKNOWN)

    def check_array_bounds(
        self,
        index: z3.ExprRef,
        length: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if array access is within bounds."""

        spec = PropertySpec(
            kind=PropertyKind.BOUNDED,
            name="Array Bounds",
            description="0 <= index < length",
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        self._solver.add(z3.Or(index < 0, index >= length))

        result = self._solver.check()

        if result == z3.unsat:
            return PropertyProof(property=spec, status=ProofStatus.PROVEN)

        elif result == z3.sat:
            model = self._solver.model()

            counterexample: dict[str, Any] = {}

            for name, var in variables.items():
                try:
                    val = model.eval(var, model_completion=True)

                    counterexample[name] = val.as_long() if z3.is_int_value(val) else str(val)

                except Exception:
                    logger.debug(
                        "Model eval failed in check_array_bounds for %s", name, exc_info=True
                    )

            return PropertyProof(
                property=spec,
                status=ProofStatus.DISPROVEN,
                counterexample=counterexample,
            )

        else:
            return PropertyProof(property=spec, status=ProofStatus.UNKNOWN)


class EquivalenceChecker:
    """Proves equivalence between different implementations.
    Useful for:
    - Verifying optimizations don't change behavior
    - Checking refactored code is equivalent to original
    - Proving algebraic simplifications are valid
    """

    def __init__(self, timeout_ms: int = 10000):
        self.timeout_ms = timeout_ms

        self._solver = z3.Solver()

        self._solver.set("timeout", timeout_ms)

    def check_equivalent(
        self,
        impl1: Callable[..., z3.ExprRef],
        impl2: Callable[..., z3.ExprRef],
        args: list[z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if two implementations are equivalent for all inputs."""

        spec = PropertySpec(
            kind=PropertyKind.EQUIVALENCE,
            name="Implementation Equivalence",
            description="impl1(*args) == impl2(*args)",
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        result1 = impl1(*args)

        result2 = impl2(*args)

        self._solver.add(result1 != result2)

        result = self._solver.check()

        if result == z3.unsat:
            return PropertyProof(property=spec, status=ProofStatus.PROVEN)

        elif result == z3.sat:
            model = self._solver.model()

            counterexample: dict[str, Any] = {}

            for i, arg in enumerate(args):
                try:
                    val = model.eval(arg, model_completion=True)

                    counterexample[f"arg{i}"] = val.as_long() if z3.is_int_value(val) else str(val)

                except Exception:
                    logger.debug(
                        "Model eval failed in check_equivalence for arg%d", i, exc_info=True
                    )

            return PropertyProof(
                property=spec,
                status=ProofStatus.DISPROVEN,
                counterexample=counterexample,
            )

        else:
            return PropertyProof(property=spec, status=ProofStatus.UNKNOWN)

    def check_refinement(
        self,
        spec_impl: Callable[..., z3.BoolRef],
        actual_impl: Callable[..., z3.BoolRef],
        args: list[z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if actual implementation refines (implies) spec.
        Verifies: actual(*args) => spec(*args)
        """

        spec = PropertySpec(
            kind=PropertyKind.REFINEMENT,
            name="Refinement Check",
            description="actual => spec",
        )

        self._solver.reset()

        for constraint in constraints or []:
            self._solver.add(constraint)

        actual_result = actual_impl(*args)

        spec_result = spec_impl(*args)

        self._solver.add(actual_result)

        self._solver.add(z3.Not(spec_result))

        result = self._solver.check()

        if result == z3.unsat:
            return PropertyProof(property=spec, status=ProofStatus.PROVEN)

        elif result == z3.sat:
            model = self._solver.model()

            counterexample: dict[str, Any] = {}

            for i, arg in enumerate(args):
                try:
                    val = model.eval(arg, model_completion=True)

                    counterexample[f"arg{i}"] = val.as_long() if z3.is_int_value(val) else str(val)

                except Exception:
                    logger.debug(
                        "Model eval failed in check_refinement for arg%d", i, exc_info=True
                    )

            return PropertyProof(
                property=spec,
                status=ProofStatus.DISPROVEN,
                counterexample=counterexample,
            )

        else:
            return PropertyProof(property=spec, status=ProofStatus.UNKNOWN)


__all__ = [
    "PropertyProver",
    "ArithmeticVerifier",
    "EquivalenceChecker",
]
