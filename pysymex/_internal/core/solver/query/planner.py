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

"""Reusable symbolic query plans for path, detector, and evidence checks.

This module intentionally centralizes the cheap-but-repeated work that used to
be open-coded around the solver boundary: conjunction construction,
``z3.simplify`` calls, top-level conjunct flattening, literal-assignment
substitution, and hard-theory AST scans.  It does not make SAT/UNSAT decisions
unless Z3 simplification returns an exact Boolean literal; solver ownership
remains in the existing solver layer.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar

import z3

from pysymex._internal.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.formula import (
    clear_formula_meta_cache,
    formula_meta,
    formula_meta_cache_stats,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

logger = get_logger(__name__)
_SIMPLIFY_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)

_ExprKey = tuple[int, int, int]
_SequenceKey = tuple[int, tuple[_ExprKey, ...]]
_LiteralSubstitution = tuple[z3.ExprRef, z3.ExprRef]
_CacheKey = TypeVar("_CacheKey")
_CacheValue = TypeVar("_CacheValue")

_QUERY_CACHE_MAX_ENTRIES = 32768
_CONJUNCT_CACHE_MAX_ENTRIES = 32768


@dataclass(frozen=True, slots=True)
class QueryCacheStats:
    """Snapshot of process-local symbolic query cache activity."""

    query_hits: int
    query_misses: int
    formula_meta_hits: int
    formula_meta_misses: int
    conjunction_hits: int
    conjunction_misses: int
    simplify_hits: int
    simplify_misses: int
    substitution_hits: int
    substitution_misses: int


_QUERY_PLAN_CACHE: OrderedDict[_SequenceKey, ConstraintQuery] = OrderedDict()
_CONJUNCT_CACHE: OrderedDict[_SequenceKey, tuple[tuple[z3.BoolRef, ...], z3.BoolRef]] = (
    OrderedDict()
)
_SIMPLIFIED_CONJUNCTION_CACHE: OrderedDict[
    _SequenceKey,
    tuple[tuple[z3.BoolRef, ...], z3.BoolRef | None],
] = OrderedDict()
_LITERAL_SUBSTITUTION_CACHE: OrderedDict[
    _SequenceKey,
    tuple[tuple[z3.BoolRef, ...], tuple[_LiteralSubstitution, ...]],
] = OrderedDict()
_LITERAL_SUBSTITUTION_RESULT_CACHE: OrderedDict[
    tuple[_SequenceKey, bool],
    tuple[tuple[z3.BoolRef, ...], bool],
] = OrderedDict()
_TOP_LEVEL_CONJUNCT_CACHE: OrderedDict[_ExprKey, tuple[z3.ExprRef, tuple[z3.ExprRef, ...]]] = (
    OrderedDict()
)

_query_hits = 0
_query_misses = 0
_conjunction_hits = 0
_conjunction_misses = 0
_simplify_hits = 0
_simplify_misses = 0
_substitution_hits = 0
_substitution_misses = 0


class ConstraintQuery:
    """Prepared, reusable view of one Boolean constraint sequence.

    Instances are immutable wrappers around the exact Z3 constraints supplied
    by callers.  They cache formula metadata and derived helper expressions, but
    they do not mutate the constraints and do not own solver state.
    """

    __slots__ = ("_constraints", "_key")

    def __init__(self, constraints: Sequence[z3.BoolRef]) -> None:
        self._constraints = tuple(constraints)
        self._key = _sequence_key(self._constraints)

    @property
    def constraints(self) -> tuple[z3.BoolRef, ...]:
        """Return the exact constraint tuple represented by this query."""
        return self._constraints

    @property
    def key(self) -> _SequenceKey:
        """Return the process-local identity key for this query."""
        return self._key

    def exact_literal_result(self) -> bool | None:
        """Return exact conjunction truth when visible from local literals."""
        saw_nontrivial = False
        for constraint in self._constraints:
            literal = exact_bool_literal(constraint)
            if literal is False:
                return False
            if literal is not True:
                saw_nontrivial = True
        return True if not saw_nontrivial else None

    def conjunction(self) -> z3.BoolRef:
        """Return the Z3 conjunction for this query, reusing identical builds."""
        return _conjunction_for_constraints(self._constraints, self._key)

    def simplified_conjunction(self) -> z3.BoolRef | None:
        """Return ``simplify_expr(And(...))`` or ``None`` if simplification fails."""
        return _simplified_conjunction(self._constraints, self._key)

    def simplifies_to_false(self) -> bool:
        """Return whether cheap simplification proves the query false."""
        literal = self.exact_literal_result()
        if literal is False:
            return True
        if literal is True:
            return False
        simplified = self.simplified_conjunction()
        return bool(simplified is not None and z3.is_false(simplified))

    def simplifies_to_true(self) -> bool:
        """Return whether cheap simplification proves the query true."""
        literal = self.exact_literal_result()
        if literal is True:
            return True
        if literal is False:
            return False
        simplified = self.simplified_conjunction()
        return bool(simplified is not None and z3.is_true(simplified))

    def literal_assignment_substitutions(self) -> tuple[_LiteralSubstitution, ...]:
        """Return top-level literal assignments asserted by this query."""
        return _literal_assignment_substitutions(self._constraints, self._key)

    def literal_substitution_yields(self, expected_literal: bool) -> bool:
        """Return whether literal-substitution simplification proves one truth value."""
        return _literal_substitution_yields(
            self._constraints,
            self._key,
            expected_literal=expected_literal,
        )

    def hard_theory_probe_constraints(self, known_sat_prefix_len: int) -> list[z3.BoolRef]:
        """Return the unverified suffix used by hard-theory skip policy."""
        if known_sat_prefix_len <= 0:
            return list(self._constraints)
        if known_sat_prefix_len >= len(self._constraints):
            return []
        return list(self._constraints[known_sat_prefix_len:])

    def contains_hard_witness_theory(self, *, include_bitvector: bool = True) -> bool:
        """Return whether any constraint contains witness-supported hard theory."""
        for constraint in self._constraints:
            meta = formula_meta(constraint)
            if meta.contains_hard_witness_theory:
                return True
            if include_bitvector and meta.contains_bitvector:
                return True
        return False

    def contains_complex_theory(self) -> bool:
        """Return whether any constraint contains a solver-expensive theory fragment."""
        return any(
            formula_meta(constraint).contains_complex_theory for constraint in self._constraints
        )

    def total_node_count(self) -> int:
        """Return the sum of cached formula node counts across top-level constraints."""
        return sum(formula_meta(constraint).node_count for constraint in self._constraints)


def symbolic_query(constraints: Iterable[z3.BoolRef] | z3.BoolRef) -> ConstraintQuery:
    """Return a prepared query plan for *constraints*.

    The returned object is process-local cacheable by Z3 AST identity.  When
    caches are disabled, a fresh object is returned and no global state is used.
    """
    global _query_hits, _query_misses
    if isinstance(constraints, z3.BoolRef):
        constraint_tuple = (constraints,)
    elif isinstance(constraints, tuple):
        constraint_tuple = constraints
    else:
        constraint_tuple = tuple(constraints)

    if is_process_cache_disabled():
        return ConstraintQuery(constraint_tuple)

    key = _sequence_key(constraint_tuple)
    cached = _QUERY_PLAN_CACHE.get(key)
    if cached is not None:
        _query_hits += 1
        _QUERY_PLAN_CACHE.move_to_end(key)
        return cached

    _query_misses += 1
    query = ConstraintQuery(constraint_tuple)
    _QUERY_PLAN_CACHE[key] = query
    _QUERY_PLAN_CACHE.move_to_end(key)
    _trim_lru(_QUERY_PLAN_CACHE, _QUERY_CACHE_MAX_ENTRIES)
    return query


def query_cache_stats() -> QueryCacheStats:
    """Return a snapshot of symbolic query cache counters."""
    meta_stats = formula_meta_cache_stats()
    return QueryCacheStats(
        query_hits=_query_hits,
        query_misses=_query_misses,
        formula_meta_hits=meta_stats.hits,
        formula_meta_misses=meta_stats.misses,
        conjunction_hits=_conjunction_hits,
        conjunction_misses=_conjunction_misses,
        simplify_hits=_simplify_hits,
        simplify_misses=_simplify_misses,
        substitution_hits=_substitution_hits,
        substitution_misses=_substitution_misses,
    )


def clear_symbolic_query_caches() -> None:
    """Clear all process-local symbolic query planner caches and counters."""
    global _query_hits, _query_misses
    global _conjunction_hits, _conjunction_misses
    global _simplify_hits, _simplify_misses
    global _substitution_hits, _substitution_misses
    _QUERY_PLAN_CACHE.clear()
    _CONJUNCT_CACHE.clear()
    _SIMPLIFIED_CONJUNCTION_CACHE.clear()
    _LITERAL_SUBSTITUTION_CACHE.clear()
    _LITERAL_SUBSTITUTION_RESULT_CACHE.clear()
    _TOP_LEVEL_CONJUNCT_CACHE.clear()
    clear_formula_meta_cache()
    _query_hits = 0
    _query_misses = 0
    _conjunction_hits = 0
    _conjunction_misses = 0
    _simplify_hits = 0
    _simplify_misses = 0
    _substitution_hits = 0
    _substitution_misses = 0


register_process_cache_clearer(
    "core.symbolic_query_planner_cache",
    clear_symbolic_query_caches,
)


def _conjunction_for_constraints(
    constraints: tuple[z3.BoolRef, ...],
    key: _SequenceKey,
) -> z3.BoolRef:
    global _conjunction_hits, _conjunction_misses
    if is_process_cache_disabled():
        return z3.And(*constraints)

    cached = _CONJUNCT_CACHE.get(key)
    if cached is not None:
        _, cached_formula = cached
        _conjunction_hits += 1
        _CONJUNCT_CACHE.move_to_end(key)
        return cached_formula

    _conjunction_misses += 1
    formula = z3.And(*constraints)
    _CONJUNCT_CACHE[key] = (constraints, formula)
    _CONJUNCT_CACHE.move_to_end(key)
    _trim_lru(_CONJUNCT_CACHE, _CONJUNCT_CACHE_MAX_ENTRIES)
    return formula


def _simplified_conjunction(
    constraints: tuple[z3.BoolRef, ...],
    key: _SequenceKey,
) -> z3.BoolRef | None:
    global _simplify_hits, _simplify_misses
    if is_process_cache_disabled():
        try:
            return simplify_expr(z3.And(*constraints))
        except _SIMPLIFY_FAILURES:
            logger.debug("Symbolic query simplification failed", exc_info=True)
            return None

    cached = _SIMPLIFIED_CONJUNCTION_CACHE.get(key)
    if cached is not None:
        _, cached_simplified = cached
        _simplify_hits += 1
        _SIMPLIFIED_CONJUNCTION_CACHE.move_to_end(key)
        return cached_simplified

    _simplify_misses += 1
    try:
        simplified = simplify_expr(_conjunction_for_constraints(constraints, key))
    except _SIMPLIFY_FAILURES:
        logger.debug("Symbolic query simplification failed", exc_info=True)
        simplified = None
    _SIMPLIFIED_CONJUNCTION_CACHE[key] = (constraints, simplified)
    _SIMPLIFIED_CONJUNCTION_CACHE.move_to_end(key)
    _trim_lru(_SIMPLIFIED_CONJUNCTION_CACHE, _QUERY_CACHE_MAX_ENTRIES)
    return simplified


def _literal_assignment_substitutions(
    constraints: tuple[z3.BoolRef, ...],
    key: _SequenceKey,
) -> tuple[_LiteralSubstitution, ...]:
    global _substitution_hits, _substitution_misses
    if is_process_cache_disabled():
        return _build_literal_assignments(constraints)

    cached = _LITERAL_SUBSTITUTION_CACHE.get(key)
    if cached is not None:
        _, cached_substitutions = cached
        _substitution_hits += 1
        _LITERAL_SUBSTITUTION_CACHE.move_to_end(key)
        return cached_substitutions

    _substitution_misses += 1
    substitutions = _build_literal_assignments(constraints)
    _LITERAL_SUBSTITUTION_CACHE[key] = (constraints, substitutions)
    _LITERAL_SUBSTITUTION_CACHE.move_to_end(key)
    _trim_lru(_LITERAL_SUBSTITUTION_CACHE, _QUERY_CACHE_MAX_ENTRIES)
    return substitutions


def _literal_substitution_yields(
    constraints: tuple[z3.BoolRef, ...],
    key: _SequenceKey,
    *,
    expected_literal: bool,
) -> bool:
    cache_key = (key, expected_literal)
    if not is_process_cache_disabled():
        cached = _LITERAL_SUBSTITUTION_RESULT_CACHE.get(cache_key)
        if cached is not None:
            _, cached_result = cached
            _LITERAL_SUBSTITUTION_RESULT_CACHE.move_to_end(cache_key)
            return cached_result

    substitutions = _literal_assignment_substitutions(constraints, key)
    if not substitutions:
        result = False
    else:
        try:
            formula = _conjunction_for_constraints(constraints, key)
            simplified = simplify_expr(z3.substitute(formula, *substitutions))
            result = z3.is_true(simplified) if expected_literal else z3.is_false(simplified)
        except _SIMPLIFY_FAILURES:
            logger.debug(
                "Symbolic query literal-substitution simplification failed",
                exc_info=True,
            )
            result = False

    if not is_process_cache_disabled():
        _LITERAL_SUBSTITUTION_RESULT_CACHE[cache_key] = (constraints, result)
        _LITERAL_SUBSTITUTION_RESULT_CACHE.move_to_end(cache_key)
        _trim_lru(_LITERAL_SUBSTITUTION_RESULT_CACHE, _QUERY_CACHE_MAX_ENTRIES)
    return result


def _build_literal_assignments(
    constraints: tuple[z3.BoolRef, ...],
) -> tuple[_LiteralSubstitution, ...]:
    substitutions: list[_LiteralSubstitution] = []
    assigned: set[tuple[int, int]] = set()
    for constraint in constraints:
        for current in _top_level_conjuncts(constraint):
            pair = _literal_assignment_pair(current)
            if pair is None:
                continue
            variable, literal = pair
            variable_key = _expr_identity(variable)
            if variable_key in assigned:
                continue
            assigned.add(variable_key)
            substitutions.append((variable, literal))
    return tuple(substitutions)


def _top_level_conjuncts(expression: z3.ExprRef) -> tuple[z3.ExprRef, ...]:
    if is_process_cache_disabled():
        return _uncached_top_level_conjuncts(expression)
    key = _expr_key(expression)
    cached = _TOP_LEVEL_CONJUNCT_CACHE.get(key)
    if cached is not None:
        cached_expression, cached_conjuncts = cached
        if cached_expression is expression:
            _TOP_LEVEL_CONJUNCT_CACHE.move_to_end(key)
            return cached_conjuncts
        _TOP_LEVEL_CONJUNCT_CACHE.pop(key, None)
    conjuncts = _uncached_top_level_conjuncts(expression)
    _TOP_LEVEL_CONJUNCT_CACHE[key] = (expression, conjuncts)
    _TOP_LEVEL_CONJUNCT_CACHE.move_to_end(key)
    _trim_lru(_TOP_LEVEL_CONJUNCT_CACHE, _QUERY_CACHE_MAX_ENTRIES)
    return conjuncts


def _uncached_top_level_conjuncts(expression: z3.ExprRef) -> tuple[z3.ExprRef, ...]:
    if z3.is_and(expression):
        conjuncts: list[z3.ExprRef] = []
        for arg in expression.children():
            conjuncts.extend(_uncached_top_level_conjuncts(arg))
        return tuple(conjuncts)
    return (expression,)


def _literal_assignment_pair(expression: z3.ExprRef) -> _LiteralSubstitution | None:
    if isinstance(expression, z3.BoolRef):
        if _is_uninterpreted_constant(expression):
            return (expression, z3.BoolVal(True, ctx=_expr_context(expression)))
        if z3.is_not(expression) and expression.num_args() == 1:
            child = expression.arg(0)
            if isinstance(child, z3.BoolRef) and _is_uninterpreted_constant(child):
                return (child, z3.BoolVal(False, ctx=_expr_context(child)))
    if not z3.is_eq(expression) or expression.num_args() != 2:
        return None
    left = expression.arg(0)
    right = expression.arg(1)
    if _is_uninterpreted_constant(left) and _is_literal_value(right):
        return (left, right)
    if _is_uninterpreted_constant(right) and _is_literal_value(left):
        return (right, left)
    return None


def _is_uninterpreted_constant(expression: z3.ExprRef) -> bool:
    return z3.is_const(expression) and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED


def _is_literal_value(expression: z3.ExprRef) -> bool:
    return (
        z3.is_true(expression)
        or z3.is_false(expression)
        or z3.is_int_value(expression)
        or z3.is_rational_value(expression)
        or z3.is_string_value(expression)
        or z3.is_bv_value(expression)
    )


def _sequence_key(constraints: Sequence[z3.BoolRef]) -> _SequenceKey:
    return (len(constraints), tuple(_expr_key(constraint) for constraint in constraints))


def _expr_key(expression: z3.ExprRef) -> _ExprKey:
    h = getattr(expression, "_symex_hash", None)
    if h is None:
        h = expression.hash()
        try:
            setattr(expression, "_symex_hash", h)
        except AttributeError:
            pass
    ast_id = getattr(expression, "_symex_id", None)
    if ast_id is None:
        ast_id = expression.get_id()
        try:
            setattr(expression, "_symex_id", ast_id)
        except AttributeError:
            pass
    ctx = expression.ctx
    ctx_id = id(ctx() if callable(ctx) else ctx)
    return (ctx_id, ast_id, h)


def _expr_identity(expression: z3.ExprRef) -> tuple[int, int]:
    ast_id = getattr(expression, "_symex_id", None)
    if ast_id is None:
        ast_id = expression.get_id()
        try:
            setattr(expression, "_symex_id", ast_id)
        except AttributeError:
            pass
    ctx = expression.ctx
    ctx_id = id(ctx() if callable(ctx) else ctx)
    return (ctx_id, ast_id)


def _expr_context(expression: z3.ExprRef) -> z3.Context:
    context = expression.ctx
    if callable(context):
        return context()
    return context


def _trim_lru(
    cache: OrderedDict[_CacheKey, _CacheValue],
    max_size: int,
) -> None:
    while len(cache) > max_size:
        cache.popitem(last=False)
