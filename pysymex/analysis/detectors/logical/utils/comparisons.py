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

"""Comparison extraction helpers for logical detectors."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex.analysis.detectors.logical.utils.expr import (
    as_bool_value,
    as_int_value,
    extract_symbol_name,
    invert_comparison,
    parse_cmp,
    unwrap_numeric,
)


def extract_var_const_comparisons(core: Iterable[z3.ExprRef]) -> list[tuple[str, str, int]]:
    """Extract comparisons such as x > 3 or x == 5 from a constraint core."""
    out: list[tuple[str, str, int]] = []
    for c in core:
        cmp_data = parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        lname = extract_symbol_name(lhs)
        rname = extract_symbol_name(rhs)
        lconst = as_int_value(lhs)
        rconst = as_int_value(rhs)

        if lname is not None and rconst is not None:
            out.append((lname, op, rconst))
            continue
        if rname is not None and lconst is not None:
            out.append((rname, invert_comparison(op), lconst))
    return out


def extract_var_var_comparisons(core: Iterable[z3.ExprRef]) -> list[tuple[str, str, str]]:
    """Extract comparisons such as x > y or a == b from a core."""
    out: list[tuple[str, str, str]] = []
    for c in core:
        cmp_data = parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        lname = extract_symbol_name(lhs)
        rname = extract_symbol_name(rhs)
        if lname is not None and rname is not None and lname != rname:
            out.append((lname, op, rname))
    return out


def _collect_additive_var_names(expr: z3.ExprRef) -> tuple[str, ...] | None:
    """Recursively collect variable names from a Z3 additive expression.

    Args:
        expr (z3.ExprRef): The Z3 expression to traverse.

    Returns:
        tuple[str, ...] | None: A tuple of extracted variable names if the expression is purely
        additive and consists of variables, otherwise None.
    """
    node = unwrap_numeric(expr)
    name = extract_symbol_name(node)
    if name is not None:
        return (name,)
    if not z3.is_app(node) or node.decl().kind() != z3.Z3_OP_ADD:
        return None

    names: list[str] = []
    for child in node.children():
        child_names = _collect_additive_var_names(child)
        if child_names is None:
            return None
        names.extend(child_names)
    return tuple(names)


def extract_sum_const_comparisons(
    core: Iterable[z3.ExprRef],
) -> list[tuple[tuple[str, ...], str, int]]:
    """Extract comparisons such as ``x + y <= 3`` for unit-coefficient sums."""
    out: list[tuple[tuple[str, ...], str, int]] = []
    for c in core:
        cmp_data = parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        left_names = _collect_additive_var_names(lhs)
        right_names = _collect_additive_var_names(rhs)
        left_const = as_int_value(lhs)
        right_const = as_int_value(rhs)

        if left_names is not None and right_const is not None and len(left_names) >= 2:
            out.append((left_names, op, right_const))
            continue
        if right_names is not None and left_const is not None and len(right_names) >= 2:
            out.append((right_names, invert_comparison(op), left_const))
    return out


def _collect_product_var_names(expr: z3.ExprRef) -> tuple[str, str] | None:
    """Collect variable names from a Z3 binary multiplication expression.

    Args:
        expr (z3.ExprRef): The Z3 expression to check.

    Returns:
        tuple[str, str] | None: A tuple of the two variable names if the expression is a binary
        multiplication of two distinct variables, otherwise None.
    """
    node = unwrap_numeric(expr)
    if not z3.is_app(node) or node.decl().kind() != z3.Z3_OP_MUL or node.num_args() != 2:
        return None
    left = extract_symbol_name(node.arg(0))
    right = extract_symbol_name(node.arg(1))
    if left is None or right is None or left == right:
        return None
    return (left, right)


def extract_product_const_comparisons(
    core: Iterable[z3.ExprRef],
) -> list[tuple[str, str, str, int]]:
    """Extract comparisons such as ``x * y < 0``."""
    out: list[tuple[str, str, str, int]] = []
    for c in core:
        cmp_data = parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        left_product = _collect_product_var_names(lhs)
        right_product = _collect_product_var_names(rhs)
        left_const = as_int_value(lhs)
        right_const = as_int_value(rhs)

        if left_product is not None and right_const is not None:
            out.append((*left_product, op, right_const))
            continue
        if right_product is not None and left_const is not None:
            out.append((*right_product, invert_comparison(op), left_const))
    return out


def extract_var_const_equalities(core: Iterable[z3.ExprRef]) -> dict[str, set[int]]:
    """Return a map of variable -> set of constant equalities from the core."""
    result: dict[str, set[int]] = {}
    for var, op, value in extract_var_const_comparisons(core):
        if op != "==":
            continue
        result.setdefault(var, set()).add(value)
    return result


def extract_var_const_disequalities(core: Iterable[z3.ExprRef]) -> dict[str, set[int]]:
    """Return a map of variable -> set of constant disequalities from the core."""
    result: dict[str, set[int]] = {}
    for var, op, value in extract_var_const_comparisons(core):
        if op != "!=":
            continue
        result.setdefault(var, set()).add(value)
    return result


def extract_bounds(core: Iterable[z3.ExprRef]) -> dict[str, dict[str, int | None]]:
    """Compute approximate integer interval bounds per variable."""
    bounds: dict[str, dict[str, int | None]] = {}
    for var, op, value in extract_var_const_comparisons(core):
        b = bounds.setdefault(
            var,
            {"min": None, "max": None, "min_strict": None, "max_strict": None},
        )
        if op == ">":
            b["min_strict"] = value if b["min_strict"] is None else max(int(b["min_strict"]), value)
        elif op == ">=":
            b["min"] = value if b["min"] is None else max(int(b["min"]), value)
        elif op == "<":
            b["max_strict"] = value if b["max_strict"] is None else min(int(b["max_strict"]), value)
        elif op == "<=":
            b["max"] = value if b["max"] is None else min(int(b["max"]), value)
    return bounds


def select_lower_bound(bounds: dict[str, int | None]) -> tuple[int, bool] | None:
    """Return the strongest lower bound as ``(value, is_strict)``."""
    min_val = bounds.get("min")
    min_strict = bounds.get("min_strict")
    candidates: list[tuple[int, bool]] = []
    if min_val is not None:
        candidates.append((int(min_val), False))
    if min_strict is not None:
        candidates.append((int(min_strict), True))
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1]))


def select_upper_bound(bounds: dict[str, int | None]) -> tuple[int, bool] | None:
    """Return the strongest upper bound as ``(value, is_strict)``."""
    max_val = bounds.get("max")
    max_strict = bounds.get("max_strict")
    candidates: list[tuple[int, bool]] = []
    if max_val is not None:
        candidates.append((int(max_val), False))
    if max_strict is not None:
        candidates.append((int(max_strict), True))
    if not candidates:
        return None
    return min(candidates, key=lambda item: (item[0], not item[1]))


def bounds_are_inconsistent(b: dict[str, int | None]) -> bool:
    """Check whether an interval descriptor is inconsistent."""
    min_val = b.get("min")
    max_val = b.get("max")
    min_strict = b.get("min_strict")
    max_strict = b.get("max_strict")

    if min_val is not None and max_val is not None and int(min_val) > int(max_val):
        return True
    if min_strict is not None and max_strict is not None and int(min_strict) >= int(max_strict):
        return True
    if min_strict is not None and max_val is not None and int(min_strict) >= int(max_val):
        return True
    if min_val is not None and max_strict is not None and int(min_val) >= int(max_strict):
        return True
    return False


def extract_modulo_equalities(core: Iterable[z3.ExprRef]) -> list[tuple[str, int, int]]:
    """Extract modulo equalities of the form x % m == r."""
    out: list[tuple[str, int, int]] = []
    for c in core:
        cmp_data = parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        if op != "==":
            continue
        lhs_val = as_int_value(lhs)
        rhs_val = as_int_value(rhs)
        if lhs_val is not None:
            mod_term = rhs
            remainder = lhs_val
        elif rhs_val is not None:
            mod_term = lhs
            remainder = rhs_val
        else:
            continue
        mod_term = unwrap_numeric(mod_term)
        if not z3.is_app(mod_term):
            continue
        if mod_term.decl().kind() not in (z3.Z3_OP_MOD, z3.Z3_OP_REM) or mod_term.num_args() != 2:
            continue
        var = extract_symbol_name(mod_term.arg(0))
        modulus = as_int_value(mod_term.arg(1))
        if var is None or modulus is None or modulus == 0:
            continue
        out.append((var, modulus, remainder))
    return out


def extract_bool_assignments(core: Iterable[z3.ExprRef]) -> dict[str, set[bool]]:
    """Extract direct boolean assignments from constraints."""
    values: dict[str, set[bool]] = {}
    for c in core:
        name = extract_symbol_name(c)
        if name is not None and z3.is_bool(c):
            values.setdefault(name, set()).add(True)
            continue

        if z3.is_not(c) and c.num_args() == 1:
            inner = c.arg(0)
            inner_name = extract_symbol_name(inner)
            if inner_name is not None and z3.is_bool(inner):
                values.setdefault(inner_name, set()).add(False)
                continue

        cmp_data = parse_cmp(c)
        if cmp_data is None:
            continue
        op, lhs, rhs = cmp_data
        if op not in ("==", "!="):
            continue
        lname = extract_symbol_name(lhs)
        rname = extract_symbol_name(rhs)
        lbool = as_bool_value(lhs)
        rbool = as_bool_value(rhs)

        if lname is not None and rbool is not None:
            values.setdefault(lname, set()).add(rbool if op == "==" else (not rbool))
        elif rname is not None and lbool is not None:
            values.setdefault(rname, set()).add(lbool if op == "==" else (not lbool))
    return values


__all__ = [
    "bounds_are_inconsistent",
    "extract_bool_assignments",
    "extract_bounds",
    "extract_modulo_equalities",
    "extract_product_const_comparisons",
    "extract_sum_const_comparisons",
    "extract_var_const_comparisons",
    "extract_var_const_disequalities",
    "extract_var_const_equalities",
    "extract_var_var_comparisons",
]
