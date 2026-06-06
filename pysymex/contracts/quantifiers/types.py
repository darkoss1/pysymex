# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""Dataclasses and enums for quantified contract syntax trees.

Shared schemas for parser, translator, instantiation, and verifier modules. Contains
no parsing or solver logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import cast

import z3

from pysymex.core.constants import Z3_TRUE, Z3_ZERO


class QuantifierKind(Enum):
    """Classification of supported quantifier forms."""

    FORALL = auto()
    EXISTS = auto()
    UNIQUE = auto()
    COUNT = auto()


@dataclass(frozen=True, slots=True)
class QuantifierVar:
    """A quantified variable bound to a Z3 sort.

    Represents a single bound variable within a quantified contract clause
    (such as ``i`` inside ``forall(i, ...)``).

    Attributes:
        name: Variable identifier.
        sort: The Z3 sort (e.g. ``IntSort``, ``BoolSort``) of this variable.
        z3_var: The resolved Z3 symbolic expression.
    """

    name: str
    sort: z3.SortRef
    z3_var: z3.ExprRef | None = None

    def __post_init__(self) -> None:
        """Initialize default Z3 variables for the quantified variable.

        If a Z3 expression is not provided during construction, creates one matching
        the specified name and Z3 sort (such as IntSort, BoolSort, or RealSort) using
        object.__setattr__ to bypass frozen dataclass mutability constraints.
        """
        if self.z3_var is None:
            if self.sort == z3.IntSort():
                object.__setattr__(self, "z3_var", z3.Int(self.name))
            elif self.sort == z3.BoolSort():
                object.__setattr__(self, "z3_var", z3.Bool(self.name))
            elif self.sort == z3.RealSort():
                object.__setattr__(self, "z3_var", z3.Real(self.name))
            else:
                object.__setattr__(self, "z3_var", z3.Const(self.name, self.sort))


@dataclass(frozen=True, slots=True)
class BoundSpec:
    """Bound specification for a quantified variable.

    Restricts the domain of the quantified variable. Supports numeric ranges
    or collection membership.

    Attributes:
        lower: Lower-bound Z3 expression.
        upper: Upper-bound Z3 expression.
        lower_inclusive: Whether the lower bound is inclusive (``<=``).
        upper_inclusive: Whether the upper bound is inclusive (``<=``).
        in_collection: Z3 array/set expression for membership bounds.
    """

    lower: z3.ExprRef | None = None
    upper: z3.ExprRef | None = None
    lower_inclusive: bool = True
    upper_inclusive: bool = False
    in_collection: z3.ExprRef | None = None

    def to_constraint(self, var: z3.ExprRef | None) -> z3.BoolRef:
        """Translate this bound specification into a Z3 boolean constraint.

        Args:
            var: The Z3 variable expression being bounded.

        Returns:
            A Z3 boolean constraint representing the range/domain limitation.

        Raises:
            ValueError: If array membership selection theory fails or is
                unsupported.
        """
        if var is None:
            return Z3_TRUE
        arith_var = cast("z3.ArithRef", var)
        constraints: list[z3.BoolRef] = []
        if self.lower is not None:
            lower = cast("z3.ArithRef", self.lower)
            if self.lower_inclusive:
                constraints.append(arith_var >= lower)
            else:
                constraints.append(arith_var > lower)
        if self.upper is not None:
            upper = cast("z3.ArithRef", self.upper)
            if self.upper_inclusive:
                constraints.append(arith_var <= upper)
            else:
                constraints.append(arith_var < upper)
        if self.in_collection is not None:
            try:
                constraints.append(z3.Select(self.in_collection, var) != Z3_ZERO)
            except z3.Z3Exception as exc:
                raise ValueError("Unsupported quantified collection membership model") from exc
        if not constraints:
            return Z3_TRUE
        return z3.And(*constraints)


@dataclass(frozen=True, slots=True)
class Quantifier:
    """A fully-parsed quantified expression.

    Holds the structured components of a quantified clause extracted from
    contract strings.

    Attributes:
        kind: The quantifier kind (FORALL, EXISTS, UNIQUE, COUNT).
        variables: List of quantified variables bound in this quantifier.
        bounds: Per-variable bound specification limits.
        body: Z3 boolean body expression.
        original_text: Raw source string from which this was parsed.
        instantiation_hints: Trigger patterns for Z3 E-matching.
    """

    kind: QuantifierKind
    variables: list[QuantifierVar]
    bounds: list[BoundSpec]
    body: z3.BoolRef
    original_text: str = ""
    instantiation_hints: list[z3.ExprRef] = field(default_factory=list[z3.ExprRef])

    def to_z3(self) -> z3.BoolRef:
        """Translate this quantifier structure into a native Z3 quantifier expression.

        Converts universal, existential, and unique existential structures.

        Returns:
            A ``z3.BoolRef`` representing the quantified formula.

        Raises:
            ValueError: If count of variables and bounds mismatch, or if
                quantifier kind is unsupported.
        """
        if len(self.variables) != len(self.bounds):
            raise ValueError("Each quantified variable requires exactly one bound")
        bound_constraints: list[z3.BoolRef] = []
        for var, bound in zip(self.variables, self.bounds, strict=True):
            bound_constraints.append(bound.to_constraint(var.z3_var))
        bound_constraint = z3.And(*bound_constraints) if bound_constraints else Z3_TRUE
        z3_vars: list[z3.ExprRef] = []
        for var in self.variables:
            if var.z3_var is not None:
                z3_vars.append(var.z3_var)
        if self.kind == QuantifierKind.FORALL:
            return z3.ForAll(z3_vars, z3.Implies(bound_constraint, self.body))
        elif self.kind == QuantifierKind.EXISTS:
            return z3.Exists(z3_vars, z3.And(bound_constraint, self.body))
        elif self.kind == QuantifierKind.UNIQUE:
            y_vars = [z3.FreshConst(v.sort, "y") for v in self.variables]
            substitutions = list(zip(z3_vars, y_vars, strict=True))
            body_with_y = z3.substitute(self.body, *substitutions)
            bound_with_y = z3.substitute(bound_constraint, *substitutions)

            eq_all = z3.And(*[x == y for x, y in zip(z3_vars, y_vars, strict=True)])
            uniqueness = z3.ForAll(y_vars, z3.Implies(z3.And(bound_with_y, body_with_y), eq_all))
            return z3.Exists(z3_vars, z3.And(bound_constraint, self.body, uniqueness))
        elif self.kind == QuantifierKind.COUNT:
            raise ValueError("COUNT quantifier requires dedicated lowering and is unsupported here")
        else:
            raise ValueError(f"Unknown quantifier kind: {self.kind}")
