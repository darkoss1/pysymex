"""Abstract Interpretation Layer for pysymex.

Implementation split for maintainability:
- domains_base: AbstractValue ABC, Interval domain
- domains_lattices: Sign, Parity, Null domains
- This file (hub): ProductDomain, AbstractState, AbstractInterpreter
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import z3

from pysymex.analysis.abstract.domains_base import (
    AbstractValue,
    Interval,
)
from pysymex.analysis.abstract.domains_lattices import (
    Null,
    NullValue,
    Parity,
    ParityValue,
    Sign,
    SignValue,
)


@dataclass
class ProductDomain:
    """
    Product of multiple abstract domains.
    Combines interval, sign, parity, etc. for more precision.
    """

    interval: Interval = field(default_factory=Interval.top)
    sign: Sign = field(default_factory=Sign.top)
    parity: Parity = field(default_factory=Parity.top)
    null: Null | None = None

    def is_bottom(self) -> bool:
        """Bottom if any component is bottom."""
        return (
            self.interval.is_bottom()
            or self.sign.is_bottom()
            or self.parity.is_bottom()
            or (self.null is not None and self.null.is_bottom())
        )

    def join(self, other: ProductDomain) -> ProductDomain:
        """Component-wise join."""
        return ProductDomain(
            interval=self.interval.join(other.interval),
            sign=self.sign.join(other.sign),
            parity=self.parity.join(other.parity),
            null=(self.null.join(other.null) if self.null and other.null else None),
        )

    def meet(self, other: ProductDomain) -> ProductDomain:
        """Component-wise meet."""
        return ProductDomain(
            interval=self.interval.meet(other.interval),
            sign=self.sign.meet(other.sign),
            parity=self.parity.meet(other.parity),
            null=(self.null.meet(other.null) if self.null and other.null else None),
        )

    def widen(self, other: ProductDomain) -> ProductDomain:
        """Component-wise widen."""
        return ProductDomain(
            interval=self.interval.widen(other.interval),
            sign=self.sign.widen(other.sign),
            parity=self.parity.widen(other.parity),
            null=(self.null.widen(other.null) if self.null and other.null else None),
        )

    def to_z3_constraint(self, var: z3.ExprRef) -> z3.BoolRef:
        """Combine all constraints."""
        constraints = [
            self.interval.to_z3_constraint(var),
            self.sign.to_z3_constraint(var),
            self.parity.to_z3_constraint(var),
        ]
        if self.null is not None:
            constraints.append(self.null.to_z3_constraint(var))
        return z3.And(*constraints)

    @classmethod
    def from_concrete(cls, value: object) -> ProductDomain:
        """Create from concrete value."""
        if isinstance(value, int):
            return cls(
                interval=Interval.from_concrete(value),
                sign=Sign.from_concrete(value),
                parity=Parity.from_concrete(value),
            )
        return cls()

    def refine(self) -> ProductDomain:
        """
        Reduce: make components consistent.
        For example, if interval is [1, 10] and sign is NEG,
        the result should be bottom.
        """
        if not self.interval.is_bottom() and not self.sign.is_bottom():
            if self.sign.value == SignValue.NEG:
                if self.interval.lo is not None and self.interval.lo >= 0:
                    return ProductDomain(
                        interval=Interval.bottom(),
                        sign=Sign.bottom(),
                        parity=Parity.bottom(),
                    )
            if self.sign.value == SignValue.POS:
                if self.interval.hi is not None and self.interval.hi <= 0:
                    return ProductDomain(
                        interval=Interval.bottom(),
                        sign=Sign.bottom(),
                        parity=Parity.bottom(),
                    )
            if self.sign.value == SignValue.ZERO:
                if not self.interval.contains(0):
                    return ProductDomain(
                        interval=Interval.bottom(),
                        sign=Sign.bottom(),
                        parity=Parity.bottom(),
                    )
        return self


@dataclass
class AbstractState:
    """
    Abstract state mapping variables to abstract values.
    """

    values: dict[str, ProductDomain] = field(default_factory=dict[str, ProductDomain])

    def get(self, name: str) -> ProductDomain:
        """Get abstract value for variable."""
        return self.values.get(name, ProductDomain())

    def set(self, name: str, value: ProductDomain) -> None:
        """Set abstract value for variable."""
        self.values[name] = value

    def join(self, other: AbstractState) -> AbstractState:
        """Join two states."""
        all_vars = set(self.values.keys()) | set(other.values.keys())
        result = AbstractState()
        for var in all_vars:
            v1 = self.get(var)
            v2 = other.get(var)
            result.set(var, v1.join(v2))
        return result

    def widen(self, other: AbstractState) -> AbstractState:
        """Widen state."""
        all_vars = set(self.values.keys()) | set(other.values.keys())
        result = AbstractState()
        for var in all_vars:
            v1 = self.get(var)
            v2 = other.get(var)
            result.set(var, v1.widen(v2))
        return result

    def to_z3_constraints(self) -> list[z3.BoolRef]:
        """Convert to Z3 constraints."""
        constraints: list[z3.BoolRef] = []
        for name, value in self.values.items():
            var = z3.Int(name)
            constraints.append(value.to_z3_constraint(var))
        return constraints

    def copy(self) -> AbstractState:
        """Create a copy."""
        result = AbstractState()
        result.values = dict(self.values.items())
        return result


class AbstractInterpreter:
    """
    Abstract interpreter for bytecode.
    Provides sound over-approximation of program behavior.
    """

    def __init__(self, widening_threshold: int = 3):
        self.widening_threshold = widening_threshold

    def analyze_assignment(
        self,
        state: AbstractState,
        target: str,
        value: ProductDomain,
    ) -> AbstractState:
        """Analyze an assignment."""
        result = state.copy()
        result.set(target, value)
        return result

    def analyze_binary_op(
        self,
        op: str,
        left: ProductDomain,
        right: ProductDomain,
    ) -> ProductDomain:
        """Analyze a binary operation."""
        if op == "+":
            return ProductDomain(
                interval=left.interval + right.interval,
                sign=self._add_signs(left.sign, right.sign),
                parity=left.parity + right.parity,
            )
        elif op == "-":
            return ProductDomain(
                interval=left.interval - right.interval,
                sign=self._sub_signs(left.sign, right.sign),
                parity=left.parity + right.parity,
            )
        elif op == "*":
            return ProductDomain(
                interval=left.interval * right.interval,
                sign=self._mul_signs(left.sign, right.sign),
                parity=left.parity * right.parity,
            )
        else:
            return ProductDomain()

    def _add_signs(self, s1: Sign, s2: Sign) -> Sign:
        """Sign of addition."""
        if s1.is_bottom() or s2.is_bottom():
            return Sign.bottom()
        if s1.is_top() or s2.is_top():
            return Sign.top()
        v1, v2 = s1.value, s2.value
        if v1 == v2 and v1 in (SignValue.POS, SignValue.NEG):
            return Sign(v1)
        if v1 == SignValue.ZERO:
            return s2
        if v2 == SignValue.ZERO:
            return s1

        if v1 == v2 and v1 in (SignValue.NON_NEG, SignValue.NON_POS):
            return Sign(v1)
        if v1 == SignValue.POS and v2 == SignValue.NON_NEG:
            return Sign(SignValue.POS)
        if v2 == SignValue.POS and v1 == SignValue.NON_NEG:
            return Sign(SignValue.POS)
        if v1 == SignValue.NEG and v2 == SignValue.NON_POS:
            return Sign(SignValue.NEG)
        if v2 == SignValue.NEG and v1 == SignValue.NON_POS:
            return Sign(SignValue.NEG)
        return Sign.top()

    def _sub_signs(self, s1: Sign, s2: Sign) -> Sign:
        """Sign of subtraction."""
        if s1.is_bottom() or s2.is_bottom():
            return Sign.bottom()
        if s2.value == SignValue.ZERO:
            return s1
        if s1.value == SignValue.ZERO:

            if s2.value == SignValue.POS:
                return Sign.negative()
            if s2.value == SignValue.NEG:
                return Sign.positive()
            return Sign.top()
        if s1.value == SignValue.POS and s2.value == SignValue.NEG:
            return Sign.positive()
        if s1.value == SignValue.NEG and s2.value == SignValue.POS:
            return Sign.negative()
        return Sign.top()

    def _mul_signs(self, s1: Sign, s2: Sign) -> Sign:
        """Sign of multiplication."""
        if s1.is_bottom() or s2.is_bottom():
            return Sign.bottom()
        if s1.value == SignValue.ZERO or s2.value == SignValue.ZERO:
            return Sign.zero()
        v1, v2 = s1.value, s2.value
        if v1 in (SignValue.POS, SignValue.NEG) and v2 in (SignValue.POS, SignValue.NEG):
            if v1 == v2:
                return Sign.positive()
            else:
                return Sign.negative()
        return Sign.top()

    def analyze_comparison(
        self,
        op: str,
        left: ProductDomain,
        right: ProductDomain,
    ) -> tuple[ProductDomain, ProductDomain]:
        """
        Analyze a comparison, returning refined values for both sides.
        For example, if x < 10 is true, refine x's interval upper bound.
        """
        left_refined = left
        right_refined = right
        if op == "<":
            if right.interval.hi is not None:
                new_hi = right.interval.hi - 1
                left_refined = ProductDomain(
                    interval=left.interval.meet(Interval(None, new_hi)),
                    sign=left.sign,
                    parity=left.parity,
                )
        elif op == "<=":
            if right.interval.hi is not None:
                left_refined = ProductDomain(
                    interval=left.interval.meet(Interval(None, right.interval.hi)),
                    sign=left.sign,
                    parity=left.parity,
                )
        elif op == ">":
            if right.interval.lo is not None:
                new_lo = right.interval.lo + 1
                left_refined = ProductDomain(
                    interval=left.interval.meet(Interval(new_lo, None)),
                    sign=left.sign,
                    parity=left.parity,
                )
        elif op == ">=":
            if right.interval.lo is not None:
                left_refined = ProductDomain(
                    interval=left.interval.meet(Interval(right.interval.lo, None)),
                    sign=left.sign,
                    parity=left.parity,
                )
        return left_refined, right_refined

    def analyze_loop(
        self,
        init_state: AbstractState,
        body: Callable[[AbstractState], AbstractState],
        max_iterations: int = 100,
    ) -> AbstractState:
        """
        Analyze a loop with widening.
        Computes fixpoint of loop body.
        """
        state = init_state.copy()
        iteration = 0
        while iteration < max_iterations:
            new_state = body(state)
            if iteration >= self.widening_threshold:
                next_state = state.widen(new_state)
            else:
                next_state = state.join(new_state)
            if self._states_equal(state, next_state):
                break
            state = next_state
            iteration += 1
        return state

    def _states_equal(self, s1: AbstractState, s2: AbstractState) -> bool:
        """Check if two states are equal."""
        all_vars = set(s1.values.keys()) | set(s2.values.keys())
        for var in all_vars:
            v1 = s1.get(var)
            v2 = s2.get(var)
            if v1 != v2:
                return False
        return True


__all__ = [
    "AbstractInterpreter",
    "AbstractState",
    "AbstractValue",
    "Interval",
    "Null",
    "NullValue",
    "Parity",
    "ParityValue",
    "ProductDomain",
    "Sign",
    "SignValue",
]
