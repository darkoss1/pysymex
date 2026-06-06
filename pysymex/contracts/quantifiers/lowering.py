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

"""Policy-driven lowering for quantified contract predicates.

This module owns quantifier strategy. It scans source predicates into
``QuantifierPredicateIR`` occurrences, finite-expands supported bounded integer
domains, and only emits native Z3 quantifiers when the caller explicitly opts in.
It does not run solver checks.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

import z3

from pysymex.contracts.ir.evidence import UnsupportedReason
from pysymex.contracts.ir.predicates import QuantifierPredicateIR, QuantifierPredicateKind
from pysymex.contracts.quantifiers.parser import (
    QuantifierParser,
    parse_quantifier_syntax,
)
from pysymex.contracts.quantifiers.translator import parse_condition_to_z3
from pysymex.contracts.quantifiers.types import BoundSpec, Quantifier, QuantifierKind
from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val


def _empty_symbolic_ranges() -> Mapping[str, "ConcreteRange"]:
    """Return the immutable empty symbolic-bound policy map."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class ConcreteRange:
    """Inclusive integer value range for a symbolic bound expression."""

    lower: int
    upper: int

    def __post_init__(self) -> None:
        """Reject impossible policy ranges early."""
        if self.upper < self.lower:
            raise ValueError("ConcreteRange upper bound must be greater than or equal to lower")


@dataclass(frozen=True, slots=True)
class QuantifierLoweringPolicy:
    """Controls finite quantifier expansion and native Z3 fallback."""

    max_expansion: int = 64
    symbolic_ranges: Mapping[str, ConcreteRange] = field(default_factory=_empty_symbolic_ranges)
    allow_native_z3: bool = False

    def __post_init__(self) -> None:
        """Freeze caller-provided maps and validate expansion limits."""
        if self.max_expansion < 0:
            raise ValueError("max_expansion must be non-negative")
        object.__setattr__(
            self,
            "symbolic_ranges",
            MappingProxyType(dict(self.symbolic_ranges)),
        )


class QuantifierLoweringError(ValueError):
    """Raised when a quantifier has no sound lowering under the active policy."""

    unsupported_reason: UnsupportedReason

    def __init__(
        self,
        message: str,
        *,
        unsupported_reason: UnsupportedReason = UnsupportedReason.UNBOUNDED_QUANTIFIER,
    ) -> None:
        """Create a lowering error with an evidence-compatible reason."""
        super().__init__(message)
        self.unsupported_reason = unsupported_reason


@dataclass(frozen=True, slots=True)
class QuantifierOccurrence:
    """One quantified predicate occurrence found in source text."""

    predicate_ir: QuantifierPredicateIR
    quantifier: Quantifier
    start: int
    end: int


DEFAULT_QUANTIFIER_LOWERING_POLICY = QuantifierLoweringPolicy()

_KEYWORDS = ("exists!", "forall", "exists")
_PREDICATE_KIND_BY_TEXT = {
    "forall": QuantifierPredicateKind.FORALL,
    "exists": QuantifierPredicateKind.EXISTS,
    "exists!": QuantifierPredicateKind.UNIQUE,
}


def find_matching_paren(text: str, start: int) -> int:
    """Find the index of the closing parenthesis matching ``text[start]``."""
    if start >= len(text) or text[start] != "(":
        return -1
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def find_quantifier_occurrences(
    condition: str,
    context: Mapping[str, z3.ExprRef] | None = None,
) -> list[QuantifierOccurrence]:
    """Return source-ordered quantified predicates in ``condition``."""
    parser = QuantifierParser(dict(context or {}))
    occurrences: list[QuantifierOccurrence] = []
    index = 0
    while index < len(condition):
        keyword = _match_keyword(condition, index)
        if keyword is None:
            index += 1
            continue
        open_index = _skip_whitespace(condition, index + len(keyword))
        if open_index >= len(condition) or condition[open_index] != "(":
            index += 1
            continue
        close_index = find_matching_paren(condition, open_index)
        if close_index == -1:
            index += 1
            continue
        source = condition[index : close_index + 1]
        quantifier = parser.parse(source)
        syntax = parse_quantifier_syntax(source)
        if quantifier is not None and syntax is not None:
            predicate_ir = QuantifierPredicateIR(
                source=source,
                quantifier_kind=_PREDICATE_KIND_BY_TEXT[syntax.kind_text],
                variable=syntax.variable,
                bound_source=syntax.bound_source,
                body_source=syntax.body_source,
            )
            occurrences.append(
                QuantifierOccurrence(
                    predicate_ir=predicate_ir,
                    quantifier=quantifier,
                    start=index,
                    end=close_index + 1,
                )
            )
            index = close_index + 1
            continue
        index += 1
    return occurrences


def lower_condition_quantifiers(
    condition: str,
    context: Mapping[str, z3.ExprRef],
    *,
    policy: QuantifierLoweringPolicy = DEFAULT_QUANTIFIER_LOWERING_POLICY,
) -> z3.BoolRef:
    """Lower all top-level quantifier calls in a string predicate."""
    occurrences = find_quantifier_occurrences(condition, context)
    if not occurrences:
        return parse_condition_to_z3(condition, context)

    lowered_context: dict[str, z3.ExprRef] = dict(context)
    pieces: list[str] = []
    cursor = 0
    for occurrence_index, occurrence in enumerate(occurrences):
        marker = f"__pysymex_quantifier_{occurrence_index}"
        pieces.append(condition[cursor : occurrence.start])
        pieces.append(marker)
        lowered_context[marker] = lower_quantifier(occurrence.quantifier, policy=policy)
        cursor = occurrence.end
    pieces.append(condition[cursor:])
    return parse_condition_to_z3("".join(pieces), lowered_context)


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
        raise QuantifierLoweringError(
            f"Quantifier {quantifier.original_text!r} requires an explicit finite range policy"
        )
    return _combine_cases(quantifier.kind, cases)


def _finite_cases(
    quantifier: Quantifier,
    policy: QuantifierLoweringPolicy,
) -> tuple[tuple[z3.BoolRef, z3.BoolRef], ...] | None:
    """Return guarded finite instantiations, or ``None`` when no finite policy applies."""
    if quantifier.kind is QuantifierKind.COUNT:
        raise QuantifierLoweringError(
            "COUNT quantifiers require dedicated lowering and are unsupported"
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
    if len(values) > policy.max_expansion:
        raise QuantifierLoweringError(
            f"Quantifier finite expansion requires {len(values)} instances, "
            f"exceeding max_expansion={policy.max_expansion}"
        )
    variable_expr = variable.z3_var
    cases: list[tuple[z3.BoolRef, z3.BoolRef]] = []
    for value in values:
        value_expr = get_int_val(value)
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
        indicators = [z3.If(z3.And(guard, body), get_int_val(1), Z3_ZERO) for guard, body in cases]
        return z3.Sum(indicators) == get_int_val(1)
    raise QuantifierLoweringError(f"Unsupported quantifier kind: {kind}")


def _match_keyword(text: str, index: int) -> str | None:
    """Return a quantifier keyword starting at ``index`` with identifier boundaries."""
    if index > 0 and _is_identifier_char(text[index - 1]):
        return None
    for keyword in _KEYWORDS:
        if not text.startswith(keyword, index):
            continue
        end = index + len(keyword)
        if keyword == "exists" and end < len(text) and text[end] == "!":
            continue
        if end < len(text) and _is_identifier_char(text[end]):
            continue
        return keyword
    return None


def _skip_whitespace(text: str, index: int) -> int:
    """Return the next non-whitespace index."""
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _is_identifier_char(char: str) -> bool:
    """Return whether ``char`` can continue a Python-like identifier."""
    return char.isalnum() or char == "_"


__all__ = [
    "ConcreteRange",
    "DEFAULT_QUANTIFIER_LOWERING_POLICY",
    "QuantifierLoweringError",
    "QuantifierLoweringPolicy",
    "QuantifierOccurrence",
    "find_matching_paren",
    "find_quantifier_occurrences",
    "lower_condition_quantifiers",
    "lower_quantifier",
]
