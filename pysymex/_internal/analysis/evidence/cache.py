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

"""Witness-variable cache for detector feasibility probes."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps

if TYPE_CHECKING:
    from collections.abc import Sequence

_WITNESS_CONSTANTS_CACHE_MAX_ENTRIES = 128


@dataclass(frozen=True, slots=True)
class WitnessConstants:
    """Collected uninterpreted variables used by detector witness probes."""

    fp_variables: list[z3.FPRef]
    integer_variables: list[z3.ArithRef]
    string_variables: list[z3.SeqRef]
    bool_variables: list[z3.BoolRef]


_WITNESS_CONSTANTS_CACHE: OrderedDict[
    tuple[int, int],
    tuple[z3.ExprRef, WitnessConstants],
] = OrderedDict()


def witness_constants(formula: z3.ExprRef) -> WitnessConstants:
    """Return detector witness variables, reusing collection for the same Z3 AST."""
    if is_process_cache_disabled():
        return collect_witness_constants(formula)

    cache_key = _witness_constants_cache_key(formula)
    cached_entry = _WITNESS_CONSTANTS_CACHE.get(cache_key)
    if cached_entry is not None:
        cached_formula, cached_constants = cached_entry
        if cached_formula is formula or Z3ExpressionOps.safe_eq(cached_formula, formula):
            _WITNESS_CONSTANTS_CACHE.move_to_end(cache_key)
            return cached_constants
        _WITNESS_CONSTANTS_CACHE.pop(cache_key, None)

    constants = collect_witness_constants(formula)
    _WITNESS_CONSTANTS_CACHE[cache_key] = (formula, constants)
    _WITNESS_CONSTANTS_CACHE.move_to_end(cache_key)
    if len(_WITNESS_CONSTANTS_CACHE) > _WITNESS_CONSTANTS_CACHE_MAX_ENTRIES:
        _WITNESS_CONSTANTS_CACHE.popitem(last=False)
    return constants


def witness_constants_from_expressions(
    expressions: Sequence[z3.ExprRef],
) -> WitnessConstants:
    """Collect witness variables from a bounded expression sequence."""
    pending: list[z3.ExprRef] = list(expressions)
    visited: set[int] = set()
    fp_variables: list[z3.FPRef] = []
    integer_by_name: dict[str, z3.ArithRef] = {}
    string_by_name: dict[str, z3.SeqRef] = {}
    bool_by_name: dict[str, z3.BoolRef] = {}
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        decl_kind = expression.decl().kind()
        if decl_kind == z3.Z3_OP_UNINTERPRETED:
            if isinstance(expression, z3.FPRef):
                fp_variables.append(expression)
                continue
            if isinstance(expression, z3.ArithRef) and expression.sort().kind() == z3.Z3_INT_SORT:
                integer_by_name[expression.decl().name()] = expression
                continue
            if isinstance(expression, z3.SeqRef) and expression.sort().kind() == z3.Z3_SEQ_SORT:
                string_by_name[expression.decl().name()] = expression
                continue
            if isinstance(expression, z3.BoolRef) and z3.is_const(expression):
                bool_by_name[expression.decl().name()] = expression
                continue
        pending.extend(expression.children())
    return WitnessConstants(
        fp_variables=fp_variables,
        integer_variables=[integer_by_name[name] for name in sorted(integer_by_name)],
        string_variables=[string_by_name[name] for name in sorted(string_by_name)],
        bool_variables=[bool_by_name[name] for name in sorted(bool_by_name)],
    )


def _witness_constants_cache_key(formula: z3.ExprRef) -> tuple[int, int]:
    """Return the process-local identity of a Z3 AST within its context."""
    return (id(formula.ctx_ref()), formula.get_id())


def clear_witness_constants_cache() -> None:
    """Clear process-local detector witness-variable cache entries."""
    _WITNESS_CONSTANTS_CACHE.clear()


register_process_cache_clearer(
    "analysis.detectors.witness_constants_cache",
    clear_witness_constants_cache,
)


def collect_witness_constants(formula: z3.ExprRef) -> WitnessConstants:
    """Collect detector witness variables from *formula* in one traversal."""
    return witness_constants_from_expressions((formula,))
