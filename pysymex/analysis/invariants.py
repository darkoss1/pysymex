# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
Class Invariants for pysymex.
Phase 19: Support for @invariant decorator and class invariant checking.
This module provides:
- @invariant decorator for class-level constraints
- InvariantChecker: Validates invariants at method boundaries
- InvariantViolation: Reports invariant failures
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import (
    Protocol,
    cast,
)

import z3

from pysymex.core.solver import create_solver


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
        """Return a human-readable string representation."""
        if self.message:
            return f"{self.condition} ({self.message})"
        return self.condition


class _InvariantOwner(Protocol):
    __invariants__: list[ClassInvariant]


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
    counterexample: dict[str, object] | None = None

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        return f"Invariant '{self.invariant}' violated at {self.when} of {self.method_name}"


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
        """Decorator."""
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
    invariants: list[ClassInvariant] = []
    for base in reversed(cls.__mro__):
        if hasattr(base, "__invariants__"):
            raw_invariants = cast("list[ClassInvariant]", base.__invariants__)
            for inv in raw_invariants:
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

    def __init__(self, solver: z3.Solver | None = None) -> None:
        self.solver = solver or create_solver()
        self._violations: list[InvariantViolation] = []
        self._checked_invariants: set[tuple[str, str, str, str]] = set()

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
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> bool:
        """
        Check if an invariant can be violated.
        Returns True if invariant holds, False if violated.
        """
        key = (inv.class_name, method_name, when, z3_condition.sexpr())
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
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[InvariantViolation]:
        """
        Check all invariants and return violations.
        """
        violations: list[InvariantViolation] = []
        for inv, cond in zip(invariants, z3_conditions, strict=False):
            if not self.check_invariant(inv, cond, when, method_name, path_constraints):
                violations.append(self._violations[-1])
        return violations

    def check_init_exit(
        self,
        invariants: list[ClassInvariant],
        z3_conditions: list[z3.BoolRef],
        path_constraints: list[z3.BoolRef] | None = None,
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
        path_constraints: list[z3.BoolRef] | None = None,
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
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[InvariantViolation]:
        """Check invariants at method exit."""
        return self.check_all_invariants(
            invariants, z3_conditions, "exit", method_name, path_constraints
        )

    def _extract_counterexample(
        self,
        model: z3.ModelRef,
    ) -> dict[str, object]:
        """Extract counterexample values from Z3 model."""
        result: dict[str, object] = {}
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

    class_invariants: dict[str, list[ClassInvariant]] = field(
        default_factory=dict[str, list[ClassInvariant]]
    )
    violations: list[InvariantViolation] = field(default_factory=list[InvariantViolation])
    _checker: InvariantChecker | None = None

    @property
    def checker(self) -> InvariantChecker:
        """Property returning the checker."""
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
    Parse an invariant condition string into Z3 using the ContractCompiler.
    """
    from pysymex.analysis.contracts.compiler import ContractCompiler

    for attr_ref in re.findall(r"self\.[A-Za-z_][A-Za-z0-9_]*", condition):
        self_attrs.setdefault(attr_ref, z3.Int(attr_ref))

    return ContractCompiler.compile_expression(condition, self_attrs)


def check_object_invariants(
    obj: object,
    invariant_state: InvariantState,
    method_name: str,
    when: str,
    path_constraints: list[z3.BoolRef] | None = None,
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
            invariants = cast("_InvariantOwner", cls).__invariants__
            invariant_state.register_class(class_name, invariants)
    if not invariants:
        return []
    self_attrs: dict[str, z3.ExprRef] = {}
    if hasattr(obj, "__dict__"):
        for attr, value in obj.__dict__.items():
            key = f"self.{attr}"
            if isinstance(value, bool):
                self_attrs[key] = z3.BoolVal(value)
            elif isinstance(value, int):
                self_attrs[key] = z3.IntVal(value)
            elif isinstance(value, float):
                self_attrs[key] = z3.RealVal(value)
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
