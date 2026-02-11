"""
Class Invariants for PySpectre.
Phase 19: Support for @invariant decorator and class invariant checking.
This module provides:
- @invariant decorator for class-level constraints
- InvariantChecker: Validates invariants at method boundaries
- InvariantViolation: Reports invariant failures
"""

from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import (
    Any,
)
import z3


@dataclass
class ClassInvariant:
    """
    Represents a class invariant.
    Invariants are boolean conditions that must hold:
    - After __init__ completes
    - Before and after every public method
    Attributes:
        condition: String expression for the invariant
        message: Optional description
        class_name: Name of the class this invariant belongs to
    """

    condition: str
    message: str | None = None
    class_name: str = ""

    def __str__(self) -> str:
        if self.message:
            return f"{self.condition} ({self.message})"
        return self.condition


@dataclass
class InvariantViolation:
    """
    Records an invariant violation.
    Attributes:
        invariant: The violated invariant
        when: "entry" or "exit" of method
        method_name: Method where violation occurred
        z3_condition: Z3 formula that was violated
        counterexample: Optional counterexample values
    """

    invariant: ClassInvariant
    when: str
    method_name: str
    z3_condition: z3.BoolRef | None = None
    counterexample: dict[str, Any] | None = None

    def __str__(self) -> str:
        return f"Invariant '{self.invariant}' violated at {self.when} " f"of {self.method_name}"


def invariant(
    condition: str,
    message: str | None = None,
) -> Callable[[type], type]:
    """
    Decorator to declare a class invariant.
    Usage:
        @invariant('self.balance >= 0', 'Balance must be non-negative')
        class BankAccount:
            def __init__(self, initial: int):
                self.balance = initial
    The invariant is checked:
    - After __init__ returns
    - Before and after every public method (not starting with _)
    """

    def decorator(cls: type) -> type:
        if not hasattr(cls, "__invariants__"):
            cls.__invariants__ = []
        cls.__invariants__.append(
            ClassInvariant(
                condition=condition,
                message=message,
                class_name=cls.__name__,
            )
        )
        return cls

    return decorator


def get_invariants(cls: type) -> list[ClassInvariant]:
    """Get all invariants for a class, including inherited ones."""
    invariants = []
    for base in reversed(cls.__mro__):
        if hasattr(base, "__invariants__"):
            for inv in base.__invariants__:
                invariants.append(
                    ClassInvariant(
                        condition=inv.condition,
                        message=inv.message,
                        class_name=cls.__name__,
                    )
                )
    return invariants


class InvariantChecker:
    """
    Checks class invariants during symbolic execution.
    For each invariant:
    1. Parse the condition into a Z3 formula
    2. Check if it can be violated given current constraints
    3. Report violations with counterexamples
    """

    def __init__(self, solver: z3.Solver | None = None):
        self.solver = solver or z3.Solver()
        self._violations: list[InvariantViolation] = []
        self._checked_invariants: set[tuple[str, str, str]] = set()

    @property
    def violations(self) -> list[InvariantViolation]:
        """Get all recorded violations."""
        return self._violations

    def clear_violations(self) -> None:
        """Clear recorded violations."""
        self._violations = []

    def check_invariant(
        self,
        inv: ClassInvariant,
        z3_condition: z3.BoolRef,
        when: str,
        method_name: str,
        path_constraints: list[z3.BoolRef] = None,
    ) -> bool:
        """
        Check if an invariant can be violated.
        Returns True if invariant holds, False if violated.
        """
        key = (inv.class_name, method_name, when)
        if key in self._checked_invariants:
            return True
        self._checked_invariants.add(key)
        self.solver.push()
        if path_constraints:
            for pc in path_constraints:
                self.solver.add(pc)
        self.solver.add(z3.Not(z3_condition))
        result = self.solver.check()
        if result == z3.sat:
            model = self.solver.model()
            counterexample = self._extract_counterexample(model)
            self._violations.append(
                InvariantViolation(
                    invariant=inv,
                    when=when,
                    method_name=method_name,
                    z3_condition=z3_condition,
                    counterexample=counterexample,
                )
            )
            self.solver.pop()
            return False
        self.solver.pop()
        return True

    def check_all_invariants(
        self,
        invariants: list[ClassInvariant],
        z3_conditions: list[z3.BoolRef],
        when: str,
        method_name: str,
        path_constraints: list[z3.BoolRef] = None,
    ) -> list[InvariantViolation]:
        """
        Check all invariants and return violations.
        """
        violations = []
        for inv, cond in zip(invariants, z3_conditions):
            if not self.check_invariant(inv, cond, when, method_name, path_constraints):
                violations.append(self._violations[-1])
        return violations

    def check_init_exit(
        self,
        invariants: list[ClassInvariant],
        z3_conditions: list[z3.BoolRef],
        path_constraints: list[z3.BoolRef] = None,
    ) -> list[InvariantViolation]:
        """Check invariants at __init__ exit."""
        return self.check_all_invariants(
            invariants, z3_conditions, "init", "__init__", path_constraints
        )

    def check_method_entry(
        self,
        invariants: list[ClassInvariant],
        z3_conditions: list[z3.BoolRef],
        method_name: str,
        path_constraints: list[z3.BoolRef] = None,
    ) -> list[InvariantViolation]:
        """Check invariants at method entry."""
        return self.check_all_invariants(
            invariants, z3_conditions, "entry", method_name, path_constraints
        )

    def check_method_exit(
        self,
        invariants: list[ClassInvariant],
        z3_conditions: list[z3.BoolRef],
        method_name: str,
        path_constraints: list[z3.BoolRef] = None,
    ) -> list[InvariantViolation]:
        """Check invariants at method exit."""
        return self.check_all_invariants(
            invariants, z3_conditions, "exit", method_name, path_constraints
        )

    def _extract_counterexample(
        self,
        model: z3.ModelRef,
    ) -> dict[str, Any]:
        """Extract counterexample values from Z3 model."""
        result = {}
        for decl in model.decls():
            name = decl.name()
            value = model[decl]
            if z3.is_int_value(value):
                result[name] = value.as_long()
            elif z3.is_bool(value):
                result[name] = z3.is_true(value)
            elif z3.is_real(value):
                result[name] = float(value.as_fraction())
            else:
                result[name] = str(value)
        return result


@dataclass
class InvariantState:
    """
    Tracks invariant state during symbolic execution.
    Attributes:
        class_invariants: Map of class name to invariants
        active_checks: Currently being verified
        violations: All violations found
    """

    class_invariants: dict[str, list[ClassInvariant]] = field(default_factory=dict)
    violations: list[InvariantViolation] = field(default_factory=list)
    _checker: InvariantChecker | None = None

    @property
    def checker(self) -> InvariantChecker:
        if self._checker is None:
            self._checker = InvariantChecker()
        return self._checker

    def register_class(
        self,
        class_name: str,
        invariants: list[ClassInvariant],
    ) -> None:
        """Register invariants for a class."""
        self.class_invariants[class_name] = invariants

    def get_invariants(self, class_name: str) -> list[ClassInvariant]:
        """Get invariants for a class."""
        return self.class_invariants.get(class_name, [])

    def record_violation(self, violation: InvariantViolation) -> None:
        """Record an invariant violation."""
        self.violations.append(violation)

    def has_violations(self) -> bool:
        """Check if any violations were found."""
        return len(self.violations) > 0

    def get_violations_for_class(
        self,
        class_name: str,
    ) -> list[InvariantViolation]:
        """Get violations for a specific class."""
        return [v for v in self.violations if v.invariant.class_name == class_name]

    def clone(self) -> InvariantState:
        """Create a copy of invariant state."""
        state = InvariantState()
        state.class_invariants = dict(self.class_invariants)
        state.violations = list(self.violations)
        return state


def parse_invariant_condition(
    condition: str,
    self_attrs: dict[str, z3.ExprRef],
) -> z3.BoolRef:
    """
    Parse an invariant condition string into Z3.
    Simple parser for conditions like:
    - 'self.x >= 0'
    - 'self.balance > self.min_balance'
    - 'self.items is not None'
    Args:
        condition: The invariant condition string
        self_attrs: Map of 'self.attr' to Z3 variables
    Returns:
        Z3 boolean expression
    """
    import re

    expr = condition
    comparisons = [
        (r"(\S+)\s*>=\s*(\S+)", lambda m: _parse_cmp(m, ">=", self_attrs)),
        (r"(\S+)\s*<=\s*(\S+)", lambda m: _parse_cmp(m, "<=", self_attrs)),
        (r"(\S+)\s*>\s*(\S+)", lambda m: _parse_cmp(m, ">", self_attrs)),
        (r"(\S+)\s*<\s*(\S+)", lambda m: _parse_cmp(m, "<", self_attrs)),
        (r"(\S+)\s*==\s*(\S+)", lambda m: _parse_cmp(m, "==", self_attrs)),
        (r"(\S+)\s*!=\s*(\S+)", lambda m: _parse_cmp(m, "!=", self_attrs)),
        (r"(\S+)\s+is\s+not\s+None", lambda m: _parse_not_none(m, self_attrs)),
        (r"(\S+)\s+is\s+None", lambda m: _parse_is_none(m, self_attrs)),
    ]
    for pattern, handler in comparisons:
        match = re.match(pattern, condition)
        if match:
            return handler(match)
    return z3.Bool(f"inv_{condition[:20]}")


def _parse_value(s: str, self_attrs: dict[str, z3.ExprRef]) -> z3.ExprRef:
    """Parse a value (self.attr or literal) to Z3."""
    s = s.strip()
    if s.startswith("self."):
        attr = s[5:]
        if s in self_attrs:
            return self_attrs[s]
        var = z3.Int(s)
        self_attrs[s] = var
        return var
    try:
        return z3.IntVal(int(s))
    except ValueError:
        pass
    try:
        return z3.RealVal(float(s))
    except ValueError:
        pass
    return z3.Int(s)


def _parse_cmp(
    match: Any,
    op: str,
    self_attrs: dict[str, z3.ExprRef],
) -> z3.BoolRef:
    """Parse a comparison expression."""
    left = _parse_value(match.group(1), self_attrs)
    right = _parse_value(match.group(2), self_attrs)
    if op == ">=":
        return left >= right
    elif op == "<=":
        return left <= right
    elif op == ">":
        return left > right
    elif op == "<":
        return left < right
    elif op == "==":
        return left == right
    elif op == "!=":
        return left != right
    return z3.BoolVal(True)


def _parse_not_none(
    match: Any,
    self_attrs: dict[str, z3.ExprRef],
) -> z3.BoolRef:
    """Parse 'x is not None' expression."""
    return z3.BoolVal(True)


def _parse_is_none(
    match: Any,
    self_attrs: dict[str, z3.ExprRef],
) -> z3.BoolRef:
    """Parse 'x is None' expression."""
    return z3.BoolVal(False)


def check_object_invariants(
    obj: Any,
    invariant_state: InvariantState,
    method_name: str,
    when: str,
    path_constraints: list[z3.BoolRef] = None,
) -> list[InvariantViolation]:
    """
    Check all invariants for an object.
    Args:
        obj: The object (with __class__ having __invariants__)
        invariant_state: The invariant tracking state
        method_name: Name of method being checked
        when: 'entry', 'exit', or 'init'
        path_constraints: Current path constraints
    Returns:
        List of violations found
    """
    cls = obj.__class__
    class_name = cls.__name__
    invariants = invariant_state.get_invariants(class_name)
    if not invariants:
        if hasattr(cls, "__invariants__"):
            invariants = cls.__invariants__
            invariant_state.register_class(class_name, invariants)
    if not invariants:
        return []
    self_attrs: dict[str, z3.ExprRef] = {}
    if hasattr(obj, "__dict__"):
        for attr, value in obj.__dict__.items():
            key = f"self.{attr}"
            if isinstance(value, int):
                self_attrs[key] = z3.IntVal(value)
            elif isinstance(value, float):
                self_attrs[key] = z3.RealVal(value)
            elif isinstance(value, bool):
                self_attrs[key] = z3.BoolVal(value)
            else:
                self_attrs[key] = z3.Int(key)
    z3_conditions = [parse_invariant_condition(inv.condition, self_attrs) for inv in invariants]
    checker = invariant_state.checker
    violations = checker.check_all_invariants(
        invariants,
        z3_conditions,
        when,
        method_name,
        path_constraints,
    )
    for v in violations:
        invariant_state.record_violation(v)
    return violations
