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

"""Finite guarded instantiation for quantified contract predicates."""

from __future__ import annotations

import z3

from pysymex._internal.contracts.quantifiers.lower.policy import (
    DEFAULT_QUANTIFIER_LOWERING_POLICY,
    ConcreteRange,
    QuantifierLoweringError,
    QuantifierLoweringPolicy,
)
from pysymex._internal.contracts.quantifiers.types import BoundSpec, Quantifier, QuantifierKind
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues


def lower_quantifier(
    quantifier: Quantifier,
    *,
    policy: QuantifierLoweringPolicy = DEFAULT_QUANTIFIER_LOWERING_POLICY,
) -> z3.BoolRef:
    """Lower one quantifier according to the supplied policy."""
    try:
        cases = _finite_cases(quantifier, policy)
    except QuantifierLoweringError:
        if policy.allow_native_z3:
            return quantifier.to_z3()
        raise
    if cases is None:
        if policy.allow_native_z3:
            return quantifier.to_z3()
        msg = f"Quantifier {quantifier.original_text!r} requires an explicit finite range policy"
        raise QuantifierLoweringError(
            msg,
        )
    return _combine_cases(quantifier.kind, cases)


def _finite_cases(
    quantifier: Quantifier,
    policy: QuantifierLoweringPolicy,
) -> tuple[tuple[z3.BoolRef, z3.BoolRef], ...] | None:
    """Return guarded finite instantiations, or ``None`` when no finite policy applies."""
    if quantifier.kind is QuantifierKind.COUNT:
        msg = "COUNT quantifiers require dedicated lowering and are unsupported"
        raise QuantifierLoweringError(
            msg,
        )
    if len(quantifier.variables) != 1 or len(quantifier.bounds) != 1:
        return None
    variable = quantifier.variables[0]
    bound = quantifier.bounds[0]
    if variable.z3_var is None or bound.in_collection is not None:
        return None
    values = _candidate_values(bound, policy)
    if values is None:
        return None
    if policy.max_expansion is not None and len(values) > policy.max_expansion:
        msg = (
            f"Quantifier finite expansion requires {len(values)} instances, "
            f"exceeding max_expansion={policy.max_expansion}"
        )
        raise QuantifierLoweringError(
            msg,
        )
    variable_expr = variable.z3_var
    cases: list[tuple[z3.BoolRef, z3.BoolRef]] = []
    for value in values:
        value_expr = ConstraintValues.int(value)
        guard = bound.to_constraint(value_expr)
        body = z3.substitute(quantifier.body, (variable_expr, value_expr))
        cases.append((guard, body))
    return tuple(cases)


def _candidate_values(
    bound: BoundSpec,
    policy: QuantifierLoweringPolicy,
) -> tuple[int, ...] | None:
    """Return all integer candidates that may satisfy a bounded range."""
    if bound.lower is None or bound.upper is None:
        return None
    lower_range = _concrete_range_for_expr(bound.lower, policy)
    upper_range = _concrete_range_for_expr(bound.upper, policy)
    if lower_range is None or upper_range is None:
        return None
    start = lower_range.lower if bound.lower_inclusive else lower_range.lower + 1
    stop = upper_range.upper + 1 if bound.upper_inclusive else upper_range.upper
    if stop <= start:
        return ()
    return tuple(range(start, stop))


def _concrete_range_for_expr(
    expr: z3.ExprRef,
    policy: QuantifierLoweringPolicy,
) -> ConcreteRange | None:
    """Resolve a Z3 integer expression to a policy-backed concrete range."""
    if z3.is_int_value(expr):
        value = expr.as_long()
        return ConcreteRange(value, value)
    for key in (expr.sexpr(), str(expr)):
        concrete_range = policy.symbolic_ranges.get(key)
        if concrete_range is not None:
            return concrete_range
    return None


def _combine_cases(
    kind: QuantifierKind,
    cases: tuple[tuple[z3.BoolRef, z3.BoolRef], ...],
) -> z3.BoolRef:
    """Combine guarded instances according to quantifier semantics."""
    if kind is QuantifierKind.FORALL:
        if not cases:
            return Z3_TRUE
        return z3.And(*[z3.Implies(guard, body) for guard, body in cases])
    if kind is QuantifierKind.EXISTS:
        if not cases:
            return Z3_FALSE
        return z3.Or(*[z3.And(guard, body) for guard, body in cases])
    if kind is QuantifierKind.UNIQUE:
        if not cases:
            return Z3_FALSE
        indicators = [
            z3.If(z3.And(guard, body), ConstraintValues.int(1), Z3_ZERO) for guard, body in cases
        ]
        return z3.Sum(indicators) == ConstraintValues.int(1)
    msg = f"Unsupported quantifier kind: {kind}"
    raise QuantifierLoweringError(msg)
