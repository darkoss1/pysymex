"""
Quantifier Types for pysymex.
Dataclasses, enums, and type-only definitions for quantifier support.
"""

from __future__ import annotations


from dataclasses import dataclass, field

from enum import Enum, auto


import z3


class QuantifierKind(Enum):
    """Types of quantifiers."""

    FORALL = auto()

    EXISTS = auto()

    UNIQUE = auto()

    COUNT = auto()


@dataclass
class QuantifierVar:
    """A quantified variable."""

    name: str

    sort: z3.SortRef

    z3_var: z3.ExprRef | None = None

    def __post_init__(self):
        if self.z3_var is None:
            if self.sort == z3.IntSort():
                self.z3_var = z3.Int(self.name)

            elif self.sort == z3.BoolSort():
                self.z3_var = z3.Bool(self.name)

            elif self.sort == z3.RealSort():
                self.z3_var = z3.Real(self.name)

            else:
                self.z3_var = z3.Const(self.name, self.sort)


@dataclass
class BoundSpec:
    """Specification of variable bounds."""

    lower: z3.ExprRef | None = None

    upper: z3.ExprRef | None = None

    lower_inclusive: bool = True

    upper_inclusive: bool = False

    in_collection: z3.ExprRef | None = None

    def to_constraint(self, var: z3.ExprRef | None) -> z3.BoolRef:
        """Convert bound to Z3 constraint."""

        if var is None:
            return z3.BoolVal(True)

        constraints: list[z3.BoolRef] = []

        if self.lower is not None:
            if self.lower_inclusive:
                constraints.append(var >= self.lower)

            else:
                constraints.append(var > self.lower)

        if self.upper is not None:
            if self.upper_inclusive:
                constraints.append(var <= self.upper)

            else:
                constraints.append(var < self.upper)

        if self.in_collection is not None:
            constraints.append(z3.BoolVal(True))

        if not constraints:
            return z3.BoolVal(True)

        return z3.And(*constraints)


@dataclass
class Quantifier:
    """Represents a quantified expression."""

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

        z3_vars = [v.z3_var for v in self.variables]

        if self.kind == QuantifierKind.FORALL:
            return z3.ForAll(z3_vars, z3.Implies(bound_constraint, self.body))

        elif self.kind == QuantifierKind.EXISTS:
            return z3.Exists(z3_vars, z3.And(bound_constraint, self.body))

        elif self.kind == QuantifierKind.UNIQUE:
            z3_vars[0] if len(z3_vars) == 1 else z3_vars

            y_vars = [z3.FreshConst(v.sort, "y") for v in self.variables]

            y_vars[0] if len(y_vars) == 1 else y_vars

            body_with_y = z3.substitute(self.body, *zip(z3_vars, y_vars, strict=False))

            bound_with_y = z3.substitute(bound_constraint, *zip(z3_vars, y_vars, strict=False))

            uniqueness = z3.ForAll(
                y_vars, z3.Implies(z3.And(bound_with_y, body_with_y), z3_vars[0] == y_vars[0])
            )

            return z3.And(z3.Exists(z3_vars, z3.And(bound_constraint, self.body)), uniqueness)

        elif self.kind == QuantifierKind.COUNT:
            raise NotImplementedError("COUNT quantifier requires special handling")

        else:
            raise ValueError(f"Unknown quantifier kind: {self.kind}")


__all__ = [
    "QuantifierKind",
    "QuantifierVar",
    "BoundSpec",
    "Quantifier",
]
