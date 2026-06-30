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

"""Shared definite-type predicates for CPython opcode diagnostics."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.values import SymbolicValue


def definite_symbolic_type_name(value: SymbolicValue) -> str | None:
    """Return a CPython type name only when a symbolic carrier has a definite type."""
    type_tag = value.type_tag
    if type_tag not in {"object", "unknown"}:
        return type_tag
    if _is_literal_true(value.is_none):
        return "NoneType"
    if _is_literal_true(value.is_bool):
        return "bool"
    if _is_literal_true(value.is_int):
        return "int"
    if _is_literal_true(value.is_float):
        return "float"
    if _is_literal_true(value.is_str):
        return "str"
    if _is_literal_true(value.is_list):
        return "list"
    if _is_literal_true(value.is_dict):
        return "dict"
    return None


def _is_literal_true(value: z3.BoolRef) -> bool:
    """Return whether a Z3 predicate is syntactically simplified to true."""
    return z3.is_true(simplify_expr(value))
