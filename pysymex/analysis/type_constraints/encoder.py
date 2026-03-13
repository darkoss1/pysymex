"""Type encoder for Z3 constraint solving.

Encodes SymbolicType instances as Z3 expressions with axioms for subtyping.
"""

from __future__ import annotations

import z3

from pysymex.analysis.type_constraints.types import SymbolicType, TypeKind


class TypeEncoder:
    """
    Encodes types as Z3 expressions for constraint solving.
    Uses an uninterpreted sort for types with axioms for subtyping.
    """

    def __init__(self):
        """Init."""
        """Initialize the class instance."""
        self.TypeSort = z3.DeclareSort("Type")
        self.int_t = z3.Const("int_t", self.TypeSort)
        self.float_t = z3.Const("float_t", self.TypeSort)
        self.bool_t = z3.Const("bool_t", self.TypeSort)
        self.str_t = z3.Const("str_t", self.TypeSort)
        self.none_t = z3.Const("none_t", self.TypeSort)
        self.any_t = z3.Const("any_t", self.TypeSort)
        self.never_t = z3.Const("never_t", self.TypeSort)
        self.object_t = z3.Const("object_t", self.TypeSort)
        self.subtype = z3.Function("subtype", self.TypeSort, self.TypeSort, z3.BoolSort())
        self.compatible = z3.Function("compatible", self.TypeSort, self.TypeSort, z3.BoolSort())
        self._type_cache: dict[SymbolicType, z3.ExprRef] = {}
        self._type_counter = 0
        self._base_axioms = self._generate_axioms()

    def _generate_axioms(self) -> list[z3.ExprRef]:
        """Generate base axioms for the type system."""
        T = z3.Const("T", self.TypeSort)
        T1 = z3.Const("T1", self.TypeSort)
        T2 = z3.Const("T2", self.TypeSort)
        T3 = z3.Const("T3", self.TypeSort)
        axioms = [
            z3.Distinct(
                self.int_t,
                self.float_t,
                self.bool_t,
                self.str_t,
                self.none_t,
                self.any_t,
                self.never_t,
                self.object_t,
            ),
            z3.ForAll([T], self.subtype(T, T)),
            z3.ForAll(
                [T1, T2, T3],
                z3.Implies(
                    z3.And(self.subtype(T1, T2), self.subtype(T2, T3)), self.subtype(T1, T3)
                ),
            ),
            z3.ForAll([T], self.subtype(T, self.any_t)),
            z3.ForAll([T], self.subtype(self.never_t, T)),
            z3.ForAll([T], z3.Implies(self.any_t != T, self.subtype(T, self.object_t))),
            self.subtype(self.bool_t, self.int_t),
            self.subtype(self.int_t, self.float_t),
            z3.ForAll([T1, T2], z3.Implies(self.subtype(T1, T2), self.compatible(T1, T2))),
        ]
        return axioms

    def encode(self, typ: SymbolicType) -> z3.ExprRef:
        """Encode a SymbolicType as a Z3 expression."""
        if typ in self._type_cache:
            return self._type_cache[typ]
        if typ.kind == TypeKind.INT:
            result = self.int_t
        elif typ.kind == TypeKind.FLOAT:
            result = self.float_t
        elif typ.kind == TypeKind.BOOL:
            result = self.bool_t
        elif typ.kind == TypeKind.STR:
            result = self.str_t
        elif typ.kind == TypeKind.NONE:
            result = self.none_t
        elif typ.kind == TypeKind.ANY:
            result = self.any_t
        elif typ.kind == TypeKind.NEVER:
            result = self.never_t
        elif typ.kind == TypeKind.OBJECT:
            result = self.object_t
        else:
            self._type_counter += 1
            result = z3.Const(f"type_{self ._type_counter }", self.TypeSort)
        self._type_cache[typ] = result
        return result

    def get_axioms(self) -> list[z3.ExprRef]:
        """Get all axioms including those for cached types."""
        return list(self._base_axioms)


__all__ = [
    "TypeEncoder",
]
