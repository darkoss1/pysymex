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

"""Exact path-fact certificates for cheap solver-query decisions.

This module owns a narrow pre-Z3 proof layer for path constraints. It recognizes
one-variable integer bounds such as ``x >= 0`` and ``x < 4``, then proves only
three outcomes:

* ``UNSAT`` when supported facts contain an exact contradiction.
* ``ENTAILED`` when every checked suffix fact is implied by a caller-supplied
  known-SAT prefix.
* ``SAT`` when the whole query is made only of supported facts and those facts
  are internally consistent.

All unsupported, mixed-theory, non-linear, multi-variable, string, array, or
otherwise unparsed constraints fall through to the normal solver path.
"""

from __future__ import annotations

from collections import OrderedDict
from enum import Enum
from typing import TYPE_CHECKING, Final

import z3

from pysymex._internal.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.solver.fact.atoms import (
    PathFactBounds,
    apply_atom,
    atom_entailed,
    atom_from_expr,
    clear_path_fact_atom_cache,
    expr_key,
)
from pysymex._internal.core.solver.fact.flattening import (
    clear_path_fact_flatten_cache,
    flatten_constraints,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class PathFactDecision(Enum):
    """Exact path-fact outcomes that may bypass a Z3 query."""

    SAT = "sat"
    UNSAT = "unsat"
    ENTAILED = "entailed"


class _PathFactSentinel(Enum):
    NEEDS_FLATTENING = "needs_flattening"


_DECISION_CACHE_MAX_SIZE: Final = 8192
_DECISION_ID_CACHE_MAX_SIZE: Final = 8192
_DECISION_CACHE: OrderedDict[
    tuple[bool, bool, bool, int | None, tuple[tuple[int, int], ...]],
    tuple[tuple[z3.BoolRef, ...], PathFactDecision | None],
] = OrderedDict()
_DECISION_ID_CACHE: OrderedDict[
    tuple[bool, bool, bool, int | None, tuple[int, ...]],
    tuple[tuple[z3.BoolRef, ...], PathFactDecision | None],
] = OrderedDict()


def _classify_path_facts(
    constraints: Iterable[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
    allow_entailed: bool = False,
    allow_prior_entailment: bool = False,
    allow_supported_sat: bool = False,
) -> PathFactDecision | None:
    """Return an exact path-fact decision for supported integer constraints.

    Args:
        constraints: Boolean Z3 path constraints.
        known_sat_prefix_len: Prefix length the caller has already established
            SAT. This is required before ``ENTAILED`` can be returned.
        allow_entailed: Whether to return ``ENTAILED`` for a fully implied
            suffix. ``UNSAT`` may be returned regardless of this flag.
        allow_prior_entailment: Permit conservative exploration-only entailment
            from earlier constraints in the same query when no known-SAT prefix
            covers them. Do not use this mode for structured solver SAT proof.
        allow_supported_sat: Whether to return ``SAT`` when every non-literal
            constraint is in the supported integer-bound fragment.

    Returns:
        ``PathFactDecision.UNSAT`` for a supported contradiction,
        ``PathFactDecision.ENTAILED`` for a suffix implied by a known-SAT prefix,
        ``PathFactDecision.SAT`` for an entirely supported satisfiable query,
        or ``None`` when the normal solver path remains necessary.

    Limitations:
        Only one-variable integer comparisons against integer literals are
        modeled. Unsupported constraints are never approximated.

    """
    constraint_list = constraints if isinstance(constraints, list) else list(constraints)
    if not constraint_list:
        return PathFactDecision.ENTAILED if allow_entailed else None

    if known_sat_prefix_len is None and not allow_prior_entailment:
        leading_decision = _leading_unsupported_decision(
            constraint_list,
            allow_entailed=allow_entailed,
        )
        if leading_decision is not _NEEDS_FLATTENING:
            return leading_decision

    if is_process_cache_disabled():
        flattened, adjusted_prefix_len = flatten_constraints(
            constraint_list,
            known_sat_prefix_len=known_sat_prefix_len,
        )
        return _uncached_classify_path_facts(
            flattened,
            adjusted_prefix_len=adjusted_prefix_len,
            allow_entailed=allow_entailed,
            allow_prior_entailment=allow_prior_entailment,
            allow_supported_sat=allow_supported_sat,
        )

    flattened, adjusted_prefix_len = flatten_constraints(
        constraint_list,
        known_sat_prefix_len=known_sat_prefix_len,
    )
    identity_cache_key = (
        allow_entailed,
        allow_prior_entailment,
        allow_supported_sat,
        adjusted_prefix_len,
        tuple(id(constraint) for constraint in flattened),
    )
    identity_cached = _DECISION_ID_CACHE.get(identity_cache_key)
    if identity_cached is not None:
        cached_constraints, cached_decision = identity_cached
        if _same_constraint_identities(cached_constraints, flattened):
            _DECISION_ID_CACHE.move_to_end(identity_cache_key)
            return cached_decision
        del _DECISION_ID_CACHE[identity_cache_key]

    cache_key = (
        allow_entailed,
        allow_prior_entailment,
        allow_supported_sat,
        adjusted_prefix_len,
        tuple(expr_key(constraint) for constraint in flattened),
    )
    cached = _DECISION_CACHE.get(cache_key)
    if cached is not None:
        cached_constraints, cached_decision = cached
        if _same_constraints(cached_constraints, flattened):
            _DECISION_CACHE.move_to_end(cache_key)
            _store_decision_identity_cache(identity_cache_key, flattened, cached_decision)
            return cached_decision
        del _DECISION_CACHE[cache_key]

    decision = _uncached_classify_path_facts(
        flattened,
        adjusted_prefix_len=adjusted_prefix_len,
        allow_entailed=allow_entailed,
        allow_prior_entailment=allow_prior_entailment,
        allow_supported_sat=allow_supported_sat,
    )
    _store_decision_cache(cache_key, flattened, decision)
    _store_decision_identity_cache(identity_cache_key, flattened, decision)
    return decision


_NEEDS_FLATTENING: Final = _PathFactSentinel.NEEDS_FLATTENING


def _leading_unsupported_decision(
    constraints: Sequence[z3.BoolRef],
    *,
    allow_entailed: bool,
) -> PathFactDecision | None | _PathFactSentinel:
    for constraint in constraints:
        literal = exact_bool_literal(constraint)
        if literal is False:
            return PathFactDecision.UNSAT
        if literal is True:
            continue
        if z3.is_and(constraint):
            return _NEEDS_FLATTENING
        if atom_from_expr(constraint) is None:
            return None
        return _NEEDS_FLATTENING
    return PathFactDecision.ENTAILED if allow_entailed else None


def clear_path_fact_caches() -> None:
    """Clear process-local path-fact AST and decision caches."""
    clear_path_fact_atom_cache()
    clear_path_fact_flatten_cache()
    _DECISION_CACHE.clear()
    _DECISION_ID_CACHE.clear()


def _uncached_classify_path_facts(
    constraints: Sequence[z3.BoolRef],
    *,
    adjusted_prefix_len: int | None,
    allow_entailed: bool,
    allow_prior_entailment: bool,
    allow_supported_sat: bool,
) -> PathFactDecision | None:
    facts: dict[str, PathFactBounds] = {}
    saw_supported_atom = False
    saw_unsupported = False
    all_suffix_atoms_entailed = True
    prefix_len = adjusted_prefix_len
    if prefix_len is None or not (0 <= prefix_len <= len(constraints)):
        prefix_len = None
    if allow_entailed and allow_prior_entailment and constraints:
        prefix_len = max(0 if prefix_len is None else prefix_len, len(constraints) - 1)

    for index, constraint in enumerate(constraints):
        literal = exact_bool_literal(constraint)
        if literal is False:
            return PathFactDecision.UNSAT
        if literal is True:
            continue

        atom = atom_from_expr(constraint)
        if atom is None:
            saw_unsupported = True
            if not allow_entailed or prefix_len is None:
                return None
            if index >= prefix_len:
                return None
            continue

        saw_supported_atom = True
        entailed = (
            allow_entailed
            and prefix_len is not None
            and index >= prefix_len
            and atom_entailed(facts, atom)
        )
        if not apply_atom(facts, atom):
            return PathFactDecision.UNSAT
        if allow_entailed and prefix_len is not None and index >= prefix_len:
            all_suffix_atoms_entailed = all_suffix_atoms_entailed and entailed

    if (
        allow_entailed
        and prefix_len is not None
        and prefix_len < len(constraints)
        and all_suffix_atoms_entailed
    ):
        return PathFactDecision.ENTAILED
    if allow_supported_sat and saw_supported_atom and not saw_unsupported:
        return PathFactDecision.SAT
    return None


def _same_constraints(left: Sequence[z3.BoolRef], right: Sequence[z3.BoolRef]) -> bool:
    if len(left) != len(right):
        return False
    return all(
        _same_constraint(left_item, right_item)
        for left_item, right_item in zip(left, right, strict=False)
    )


def _same_constraint_identities(
    left: Sequence[z3.BoolRef],
    right: Sequence[z3.BoolRef],
) -> bool:
    if len(left) != len(right):
        return False
    return all(left_item is right_item for left_item, right_item in zip(left, right, strict=False))


def _same_constraint(left: z3.BoolRef, right: z3.BoolRef) -> bool:
    return left is right or z3.eq(left, right)


def _store_decision_cache(
    key: tuple[bool, bool, bool, int | None, tuple[tuple[int, int], ...]],
    constraints: tuple[z3.BoolRef, ...],
    decision: PathFactDecision | None,
) -> None:
    _DECISION_CACHE[key] = (constraints, decision)
    _DECISION_CACHE.move_to_end(key)
    if len(_DECISION_CACHE) > _DECISION_CACHE_MAX_SIZE:
        _DECISION_CACHE.popitem(last=False)


def _store_decision_identity_cache(
    key: tuple[bool, bool, bool, int | None, tuple[int, ...]],
    constraints: tuple[z3.BoolRef, ...],
    decision: PathFactDecision | None,
) -> None:
    _DECISION_ID_CACHE[key] = (constraints, decision)
    _DECISION_ID_CACHE.move_to_end(key)
    if len(_DECISION_ID_CACHE) > _DECISION_ID_CACHE_MAX_SIZE:
        _DECISION_ID_CACHE.popitem(last=False)


register_process_cache_clearer(
    "core.path_fact_caches",
    clear_path_fact_caches,
)


class PathFactPolicy:
    """Policy owner for exact integer path-fact solver shortcuts."""

    @staticmethod
    def classify(
        constraints: Iterable[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
        allow_entailed: bool = False,
        allow_prior_entailment: bool = False,
        allow_supported_sat: bool = False,
    ) -> PathFactDecision | None:
        """Return an exact path-fact decision for supported integer constraints."""
        return _classify_path_facts(
            constraints,
            known_sat_prefix_len=known_sat_prefix_len,
            allow_entailed=allow_entailed,
            allow_prior_entailment=allow_prior_entailment,
            allow_supported_sat=allow_supported_sat,
        )
