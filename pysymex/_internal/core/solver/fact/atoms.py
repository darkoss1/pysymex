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

"""One-variable integer atom extraction for path-fact certificates."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Final

import z3

from pysymex._internal.core.cache.control import is_process_cache_disabled


@dataclass(frozen=True, slots=True)
class PathFactAtom:
    """Supported one-variable integer comparison against a literal."""

    variable: str
    op: str
    value: int


def _new_int_set() -> set[int]:
    return set()


@dataclass(slots=True)
class PathFactBounds:
    """Accumulated exact integer bounds for one symbolic variable."""

    lower: int | None = None
    upper: int | None = None
    not_equal: set[int] = field(default_factory=_new_int_set)


_ATOM_CACHE_MAX_SIZE: Final = 32768
_ATOM_ID_CACHE_MAX_SIZE: Final = 32768
_ATOM_CACHE: OrderedDict[
    tuple[int, int],
    tuple[z3.BoolRef, PathFactAtom | None],
] = OrderedDict()
_ATOM_ID_CACHE: OrderedDict[
    int,
    tuple[z3.BoolRef, PathFactAtom | None],
] = OrderedDict()
_COMPARISON_OP_BY_DECL_KIND: Final = {
    z3.Z3_OP_LT: "<",
    z3.Z3_OP_LE: "<=",
    z3.Z3_OP_GT: ">",
    z3.Z3_OP_GE: ">=",
    z3.Z3_OP_EQ: "==",
    z3.Z3_OP_DISTINCT: "!=",
}


def _get_decl_name_string(decl: z3.FuncDeclRef) -> str:
    name_str = getattr(decl, "_symex_name", None)
    if name_str is None:
        name_str = str(decl.name())
        try:
            setattr(decl, "_symex_name", name_str)
        except AttributeError:
            pass
    return name_str


def atom_from_expr(expr: z3.BoolRef) -> PathFactAtom | None:
    """Return a supported path-fact atom for ``expr``, if exact and cached."""
    if is_process_cache_disabled():
        return uncached_atom_from_expr(expr)

    identity_key = id(expr)
    identity_cached = _ATOM_ID_CACHE.get(identity_key)
    if identity_cached is not None:
        cached_expr, cached_atom = identity_cached
        if cached_expr is expr:
            _ATOM_ID_CACHE.move_to_end(identity_key)
            return cached_atom
        del _ATOM_ID_CACHE[identity_key]

    key = expr_key(expr)
    cached = _ATOM_CACHE.get(key)
    if cached is not None:
        _, cached_atom = cached
        _ATOM_CACHE.move_to_end(key)
        _store_atom_identity_cache(identity_key, expr, cached_atom)
        return cached_atom

    atom = uncached_atom_from_expr(expr)
    _ATOM_CACHE[key] = (expr, atom)
    _ATOM_CACHE.move_to_end(key)
    if len(_ATOM_CACHE) > _ATOM_CACHE_MAX_SIZE:
        _ATOM_CACHE.popitem(last=False)
    _store_atom_identity_cache(identity_key, expr, atom)
    return atom


def uncached_atom_from_expr(expr: z3.BoolRef) -> PathFactAtom | None:
    """Return a supported path-fact atom without consulting process caches."""
    if z3.is_not(expr) and expr.num_args() == 1:
        child = expr.arg(0)
        if not isinstance(child, z3.BoolRef):
            return None
        inner = atom_from_expr(child)
        if inner is None:
            return None
        negated = _negate_op(inner.op)
        return None if negated is None else PathFactAtom(inner.variable, negated, inner.value)

    op = _comparison_op(expr)
    if op is None or expr.num_args() != 2:
        return None

    left = expr.arg(0)
    right = expr.arg(1)
    if _is_int_variable(left) and z3.is_int_value(right):
        return PathFactAtom(_get_decl_name_string(left.decl()), op, int(right.as_long()))
    if z3.is_int_value(left) and _is_int_variable(right):
        return PathFactAtom(_get_decl_name_string(right.decl()), _flip_op(op), int(left.as_long()))
    return None


def apply_atom(facts: dict[str, PathFactBounds], atom: PathFactAtom) -> bool:
    """Apply ``atom`` to bounds and return whether the bounds stay consistent."""
    bounds = facts.get(atom.variable)
    if bounds is None:
        bounds = PathFactBounds()
        facts[atom.variable] = bounds

    if atom.op == "<":
        upper = atom.value - 1
        bounds.upper = upper if bounds.upper is None else min(bounds.upper, upper)
    elif atom.op == "<=":
        bounds.upper = atom.value if bounds.upper is None else min(bounds.upper, atom.value)
    elif atom.op == ">":
        lower = atom.value + 1
        bounds.lower = lower if bounds.lower is None else max(bounds.lower, lower)
    elif atom.op == ">=":
        bounds.lower = atom.value if bounds.lower is None else max(bounds.lower, atom.value)
    elif atom.op == "==":
        bounds.lower = atom.value if bounds.lower is None else max(bounds.lower, atom.value)
        bounds.upper = atom.value if bounds.upper is None else min(bounds.upper, atom.value)
    elif atom.op == "!=":
        bounds.not_equal.add(atom.value)
    else:
        return False
    return bounds_are_consistent(bounds)


def bounds_are_consistent(bounds: PathFactBounds) -> bool:
    """Return whether accumulated integer bounds still admit a value."""
    if bounds.lower is None or bounds.upper is None:
        return True
    if bounds.lower > bounds.upper:
        return False
    range_size = bounds.upper - bounds.lower + 1
    excluded_in_range = sum(
        1 for value in bounds.not_equal if bounds.lower <= value <= bounds.upper
    )
    return excluded_in_range < range_size


def atom_entailed(facts: dict[str, PathFactBounds], atom: PathFactAtom) -> bool:
    """Return whether existing bounds imply ``atom``."""
    bounds = facts.get(atom.variable)
    if bounds is None:
        return False
    if atom.op == "<":
        return bounds.upper is not None and bounds.upper < atom.value
    if atom.op == "<=":
        return bounds.upper is not None and bounds.upper <= atom.value
    if atom.op == ">":
        return bounds.lower is not None and bounds.lower > atom.value
    if atom.op == ">=":
        return bounds.lower is not None and bounds.lower >= atom.value
    if atom.op == "==":
        return bounds.lower == atom.value and bounds.upper == atom.value
    if atom.op == "!=":
        return (
            atom.value in bounds.not_equal
            or (bounds.lower is not None and bounds.lower > atom.value)
            or (bounds.upper is not None and bounds.upper < atom.value)
        )
    return False


def expr_key(expr: z3.ExprRef) -> tuple[int, int]:
    """Return a process-local key for a Z3 AST within its context."""
    ast_id = getattr(expr, "_symex_id", None)
    if ast_id is None:
        ast_id = expr.get_id()
        try:
            setattr(expr, "_symex_id", ast_id)
        except AttributeError:
            pass
    ctx = expr.ctx
    ctx_id = id(ctx() if callable(ctx) else ctx)
    return (ctx_id, ast_id)


def clear_path_fact_atom_cache() -> None:
    """Clear atom extraction cache entries."""
    _ATOM_CACHE.clear()
    _ATOM_ID_CACHE.clear()


def _store_atom_identity_cache(
    key: int,
    expr: z3.BoolRef,
    atom: PathFactAtom | None,
) -> None:
    _ATOM_ID_CACHE[key] = (expr, atom)
    _ATOM_ID_CACHE.move_to_end(key)
    if len(_ATOM_ID_CACHE) > _ATOM_ID_CACHE_MAX_SIZE:
        _ATOM_ID_CACHE.popitem(last=False)


def _comparison_op(expr: z3.ExprRef) -> str | None:
    return _COMPARISON_OP_BY_DECL_KIND.get(expr.decl().kind())


def _is_int_variable(expr: z3.ExprRef) -> bool:
    return (
        expr.num_args() == 0 and expr.sort().kind() == z3.Z3_INT_SORT and not z3.is_int_value(expr)
    )


def _flip_op(op: str) -> str:
    return {
        "<": ">",
        "<=": ">=",
        ">": "<",
        ">=": "<=",
        "==": "==",
        "!=": "!=",
    }[op]


def _negate_op(op: str) -> str | None:
    return {
        "<": ">=",
        "<=": ">",
        ">": "<=",
        ">=": "<",
        "==": "!=",
        "!=": "==",
    }.get(op)
