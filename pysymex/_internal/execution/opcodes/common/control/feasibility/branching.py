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

"""Conditional branch opcodes with solver-backed feasibility splitting.

Owns ``POP_JUMP_*``, ``JUMP_IF_TRUE/FALSE``, and truthiness lowering that forks
``VMState`` when both outcomes remain satisfiable. Uses
:func:`pysymex._internal.core.solver.engine.path_may_be_feasible` with explicit unknown handling;
does not emit detector issues directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.chain import ConstraintChain
from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.solver.constraints.theory import (
    constraints_include_bitvector_smt_theory,
    is_bitvector_smt_theory,
)
from pysymex._internal.core.solver.query.planner import formula_meta, symbolic_query
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    STRING_WITNESS_EXPR_CACHE as _STRING_WITNESS_EXPR_CACHE,
)
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    STRING_WITNESS_TERMS_CACHE as _STRING_WITNESS_TERMS_CACHE,
)
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    clear_string_witness_caches,
)
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    has_string_witness_terms as _has_string_witness_terms,
)
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    is_string_witness_term as _is_string_witness_term,
)
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    string_witness_expr_cache_key as _string_witness_expr_cache_key,
)
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    string_witness_expr_cache_lookup as _string_witness_expr_cache_lookup,
)
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    string_witness_expr_cache_store as _string_witness_expr_cache_store,
)
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    string_witness_terms_cache_key as _string_witness_terms_cache_key,
)
from pysymex._internal.execution.opcodes.common.control.feasibility.witnesses import (
    uncached_has_string_witness_terms as _uncached_has_string_witness_terms,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = get_logger(__name__)

_BRANCH_WITNESS_COMPAT_EXPORTS = (
    _STRING_WITNESS_EXPR_CACHE,
    _STRING_WITNESS_TERMS_CACHE,
    _is_string_witness_term,
    _string_witness_expr_cache_key,
    _string_witness_expr_cache_lookup,
    _string_witness_expr_cache_store,
    _string_witness_terms_cache_key,
    _uncached_has_string_witness_terms,
    clear_string_witness_caches,
)


def _contains_sequence_linear_only(
    constraints: list[z3.BoolRef],
    chain: ConstraintChain | None = None,
    extra: z3.BoolRef | None = None,
) -> bool:
    """Return whether a branch query is sequence/linear arithmetic only.

    String-model branch guards frequently mix sequence predicates with linear
    integer side constraints emitted by lightweight models such as ``count``
    and ``rfind``.  Solving each pair eagerly is expensive, and the executor
    already treats hard-theory branch checks optimistically for bit-vectors.
    This keeps that optimistic policy for pure string/sequence-linear branch
    queries while still excluding theories where the witness solver should own
    pruning.
    """
    if chain is not None and extra is not None:
        meta = formula_meta(extra)
        has_seq = chain.has_sequence_theory() or meta.contains_sequence
        has_excl = chain.has_excluded_theory() or bool(
            meta.contains_bitvector
            or meta.contains_float
            or meta.contains_array
            or meta.contains_modulo
            or meta.contains_division
            or meta.contains_nonlinear_mul
        )
        return has_seq and not has_excl
    return _contains_sequence_linear_only_uncached(constraints)


def _contains_sequence_linear_only_uncached(constraints: list[z3.BoolRef]) -> bool:
    saw_sequence = False
    for constraint in constraints:
        if exact_bool_literal(constraint) is not None:
            continue
        meta = formula_meta(constraint)
        if (
            meta.contains_bitvector
            or meta.contains_float
            or meta.contains_array
            or meta.contains_modulo
            or meta.contains_division
            or meta.contains_nonlinear_mul
        ):
            return False
        saw_sequence = saw_sequence or meta.contains_sequence
    return saw_sequence


def _sequence_linear_branch_feasibility(
    constraints: list[z3.BoolRef],
    chain: ConstraintChain | None = None,
    extra: z3.BoolRef | None = None,
) -> bool | None:
    """Return cheap feasibility for sequence-linear branch queries, if applicable."""
    if not _contains_sequence_linear_only(constraints, chain=chain, extra=extra):
        return None
    query = symbolic_query(tuple(constraints))
    if query.exact_literal_result() is False:
        return False
    if query.literal_substitution_yields(False):
        return False
    if query.simplifies_to_false():
        return False
    logger.debug("Skipping expensive branch feasibility query for sequence-linear SMT path context")
    return True


def _is_sat_with_extra(
    constraints: Iterable[z3.BoolRef],
    extra: z3.BoolRef,
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    """Return whether path constraints remain satisfiable with an extra literal."""
    from pysymex._internal.core.solver.engine.policies import path_may_be_feasible

    literal = exact_bool_literal(extra)
    if literal is False:
        return False
    if literal is True:
        constraint_list = list(constraints)
        if _prefix_known_sat(constraint_list, known_sat_prefix_len):
            return True
        return path_may_be_feasible(
            constraint_list,
            known_sat_prefix_len=known_sat_prefix_len,
        )
    if is_bitvector_smt_theory(extra):
        logger.debug("Skipping expensive branch feasibility query for bit-vector SMT path context")
        return True

    chain = constraints if isinstance(constraints, ConstraintChain) else None
    if isinstance(constraints, ConstraintChain):
        if constraints.has_bitvector_smt_theory():
            logger.debug(
                "Skipping expensive branch feasibility query for bit-vector SMT path context",
            )
            return True
        constraint_list = constraints.to_list()
    else:
        constraint_list = list(constraints)
        if constraints_include_bitvector_smt_theory(constraint_list):
            logger.debug(
                "Skipping expensive branch feasibility query for bit-vector SMT path context",
            )
            return True

    constraint_list.append(extra)
    try:
        sequence_decision = _sequence_linear_branch_feasibility(
            constraint_list,
            chain=chain,
            extra=extra,
        )
        if sequence_decision is not None:
            return sequence_decision
        return path_may_be_feasible(
            constraint_list,
            known_sat_prefix_len=known_sat_prefix_len,
        )
    finally:
        constraint_list.pop()


def _constraints_as_list_for_branch(
    constraints: Iterable[z3.BoolRef],
) -> list[z3.BoolRef] | None:
    """Materialize constraints once for paired branch checks.

    ``None`` means preserve existing bit-vector branch behavior: skip expensive
    feasibility queries and keep both symbolic outcomes alive.
    """
    if isinstance(constraints, ConstraintChain):
        if constraints.has_bitvector_smt_theory():
            logger.debug(
                "Skipping expensive branch feasibility query for bit-vector SMT path context",
            )
            return None
        return constraints.to_list()

    constraint_list = list(constraints)
    if constraints_include_bitvector_smt_theory(constraint_list):
        logger.debug("Skipping expensive branch feasibility query for bit-vector SMT path context")
        return None
    return constraint_list


def _are_complement_literals(first_extra: z3.BoolRef, second_extra: z3.BoolRef) -> bool:
    """Return whether two branch conditions are syntactic Boolean complements."""
    return (
        z3.is_not(second_extra)
        and second_extra.num_args() == 1
        and z3.eq(second_extra.arg(0), first_extra)
    ) or (
        z3.is_not(first_extra)
        and first_extra.num_args() == 1
        and z3.eq(first_extra.arg(0), second_extra)
    )


def _prefix_known_sat(
    constraint_list: list[z3.BoolRef],
    known_sat_prefix_len: int | None,
) -> bool:
    """Return whether the full current branch prefix is already SAT-certified."""
    return (
        known_sat_prefix_len is not None
        and known_sat_prefix_len >= 0
        and known_sat_prefix_len >= len(constraint_list)
    )


def branch_feasible_pair(
    constraints: Iterable[z3.BoolRef],
    first_extra: z3.BoolRef,
    second_extra: z3.BoolRef,
    *,
    known_sat_prefix_len: int | None = None,
) -> tuple[bool, bool]:
    """Return feasibility for two branch literals sharing the same path prefix.

    This is a merge-safe optimization for POP_JUMP-style splits: it avoids
    duplicate ConstraintChain traversal, duplicate bit-vector theory probing,
    and short-lived branch-list allocation while preserving the same
    SAT/UNKNOWN policy as :func:`branch_feasible`.

    The complementary-survivor shortcut only fires when the current prefix is
    already SAT-certified by the executor. If that proof is unavailable, both
    branches are checked through the normal optimistic feasibility policy.
    """
    from pysymex._internal.core.solver.engine.policies import path_may_be_feasible

    first_literal = exact_bool_literal(first_extra)
    second_literal = exact_bool_literal(second_extra)

    if first_literal is False and second_literal is False:
        return False, False

    chain = constraints if isinstance(constraints, ConstraintChain) else None

    if first_literal is True or second_literal is True:
        constraint_list = list(constraints)
    elif is_bitvector_smt_theory(first_extra) or is_bitvector_smt_theory(second_extra):
        logger.debug("Skipping expensive branch feasibility query for bit-vector SMT branch")
        return True, True
    else:
        materialized = _constraints_as_list_for_branch(constraints)
        if materialized is None:
            return True, True
        constraint_list = materialized

    prefix_is_known_sat = _prefix_known_sat(constraint_list, known_sat_prefix_len)
    can_use_complement_survivor = prefix_is_known_sat and _are_complement_literals(
        first_extra,
        second_extra,
    )

    def check(extra: z3.BoolRef, literal: bool | None) -> bool:
        if literal is False:
            return False
        if literal is True:
            if prefix_is_known_sat:
                return True
            return path_may_be_feasible(
                constraint_list,
                known_sat_prefix_len=known_sat_prefix_len,
            )
        if is_bitvector_smt_theory(extra):
            logger.debug("Skipping expensive branch feasibility query for bit-vector SMT branch")
            return True
        constraint_list.append(extra)
        try:
            sequence_decision = _sequence_linear_branch_feasibility(
                constraint_list,
                chain=chain,
                extra=extra,
            )
            if sequence_decision is not None:
                return sequence_decision
            return path_may_be_feasible(
                constraint_list,
                known_sat_prefix_len=known_sat_prefix_len,
            )
        finally:
            constraint_list.pop()

    first_feasible = check(first_extra, first_literal)
    if not first_feasible and can_use_complement_survivor:
        return False, True

    second_feasible = check(second_extra, second_literal)
    if not second_feasible and can_use_complement_survivor:
        return True, False

    return first_feasible, second_feasible


def branch_feasible(
    constraints: Iterable[z3.BoolRef],
    extra: z3.BoolRef,
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    """Return branch feasibility through the solver source of truth."""
    return _is_sat_with_extra(
        constraints,
        extra,
        known_sat_prefix_len=known_sat_prefix_len,
    )


def preferred_truth_order(
    constraints: Iterable[z3.BoolRef],
    cond_expr: z3.BoolRef,
    not_cond_expr: z3.BoolRef,
    *,
    default_order: tuple[bool, bool] = (True, False),
) -> tuple[bool, bool]:
    """Return branch truth order, preferring a concrete string/integer witness if any."""
    if not _has_string_witness_terms((cond_expr,)):
        return default_order
    constraint_list = list(constraints)
    if not constraint_list:
        return default_order

    from pysymex._internal.analysis.evidence.strings import (
        string_integer_context_truth_value,
        string_integer_witness_model,
    )

    preferred_truth = string_integer_context_truth_value(constraint_list, cond_expr)
    if preferred_truth is not None:
        return (preferred_truth, not preferred_truth)
    true_has_witness = string_integer_witness_model([*constraint_list, cond_expr]) is not None
    false_has_witness = string_integer_witness_model([*constraint_list, not_cond_expr]) is not None
    if false_has_witness and not true_has_witness:
        return (False, True)
    return default_order


_preferred_truth_order = preferred_truth_order
