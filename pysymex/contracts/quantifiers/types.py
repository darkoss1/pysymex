# pysymex: Python Symbolic Execution & Formal Verification
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

"""
Quantifier Types for pysymex.
Dataclasses, enums, and type-only definitions for quantifier support.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import cast

import z3


class QuantifierKind(Enum):
    """Classification of supported quantifier forms."""

    FORALL = auto()
    EXISTS = auto()
    UNIQUE = auto()
    COUNT = auto()


@dataclass(frozen=True, slots=True)
class QuantifierVar:
    """A quantified variable bound to a Z3 sort.

    Attributes:
        name: Variable identifier.
        sort: Z3 sort (IntSort, BoolSort, etc.).
        z3_var: Resolved Z3 expression (auto-created in ``__post_init__``).
    """

    name: str
    sort: z3.SortRef
    z3_var: z3.ExprRef | None = None

    def __post_init__(self) -> None:
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

    At most one of the numeric bounds or ``in_collection`` should be set.

    Attributes:
        lower: Lower-bound Z3 expression.
        upper: Upper-bound Z3 expression.
        lower_inclusive: Whether lower bound is inclusive.
        upper_inclusive: Whether upper bound is inclusive.
        in_collection: Z3 array/set expression for membership bounds.
    """

    lower: z3.ExprRef | None = None
    upper: z3.ExprRef | None = None
    lower_inclusive: bool = True
    upper_inclusive: bool = False
    in_collection: z3.ExprRef | None = None

    def to_constraint(self, var: z3.ExprRef | None) -> z3.BoolRef:
        """Convert bound to Z3 constraint."""
        if var is None:
            return z3.BoolVal(True)
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
                constraints.append(z3.Select(self.in_collection, var) != z3.IntVal(0))
            except z3.Z3Exception:
                pass
        if not constraints:
            return z3.BoolVal(True)
        return z3.And(*constraints)


@dataclass(frozen=True, slots=True)
class Quantifier:
    """A fully-parsed quantified expression.

    Attributes:
        kind: Quantifier type (FORALL, EXISTS, UNIQUE, COUNT).
        variables: Bound quantifier variables.
        bounds: Per-variable bound specifications.
        body: Z3 Boolean body expression.
        original_text: Source text the quantifier was parsed from.
        instantiation_hints: Optional Z3 trigger expressions.
    """

    kind: QuantifierKind
    variables: list[QuantifierVar]
    bounds: list[BoundSpec]
    body: z3.BoolRef
    original_text: str = ""
    instantiation_hints: list[z3.ExprRef] = field(default_factory=list[z3.ExprRef])

    def to_z3(self) -> z3.BoolRef:
        """Convert to Z3 quantified formula."""
        bound_constraints: list[z3.BoolRef] = []
        for var, bound in zip(self.variables, self.bounds, strict=False):
            bound_constraints.append(bound.to_constraint(var.z3_var))
        bound_constraint = z3.And(*bound_constraints) if bound_constraints else z3.BoolVal(True)
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
            body_with_y = z3.substitute(self.body, *zip(z3_vars, y_vars, strict=False))
            bound_with_y = z3.substitute(bound_constraint, *zip(z3_vars, y_vars, strict=False))

            eq_all = z3.And(*[x == y for x, y in zip(z3_vars, y_vars, strict=False)])
            uniqueness = z3.ForAll(y_vars, z3.Implies(z3.And(bound_with_y, body_with_y), eq_all))
            return z3.And(z3.Exists(z3_vars, z3.And(bound_constraint, self.body)), uniqueness)
        elif self.kind == QuantifierKind.COUNT:
            raise NotImplementedError("COUNT quantifier requires special handling")
        else:
            raise ValueError(f"Unknown quantifier kind: {self.kind}")


__all__ = [
    "BoundSpec",
    "Quantifier",
    "QuantifierKind",
    "QuantifierVar",
]
