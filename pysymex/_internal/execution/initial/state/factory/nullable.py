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

"""Nullable symbolic input carrier creation."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.types.hints import (
    SymbolicHintKind,
    canonicalize_symbolic_type_hint,
    parse_fixed_tuple_type_hint,
    symbolic_hint_kind,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.execution.initial.state.types import SymbolicCreatedValue


def create_nullable_symbolic_for_type(
    name: str,
    inner_type_hint: str,
) -> tuple[SymbolicCreatedValue, z3.BoolRef]:
    """Create a symbolic value constrained to ``None`` or one non-null type."""
    sym_val, constraint = SymbolicValue.symbolic(name)
    type_hint = canonicalize_symbolic_type_hint(inner_type_hint)
    kind = symbolic_hint_kind(type_hint)
    type_branch: z3.BoolRef | None = None
    extra_constraint: z3.BoolRef = z3.BoolVal(True)
    if kind == SymbolicHintKind.INT:
        type_branch = sym_val.is_int
    elif kind == SymbolicHintKind.FLOAT:
        type_branch = sym_val.is_float
    elif kind == SymbolicHintKind.STR:
        type_branch = sym_val.is_str
    elif kind == SymbolicHintKind.BYTES:
        type_branch = sym_val.is_bytes
    elif kind == SymbolicHintKind.BOOL:
        type_branch = sym_val.is_bool
    elif kind == SymbolicHintKind.PATH:
        type_branch = sym_val.is_path
    elif kind in {SymbolicHintKind.LIST, SymbolicHintKind.BYTEARRAY}:
        type_branch = sym_val.is_list
    elif kind == SymbolicHintKind.TUPLE:
        type_branch = sym_val.is_tuple
        fixed_tuple = parse_fixed_tuple_type_hint(type_hint)
        if fixed_tuple is not None:
            extra_constraint = sym_val.z3_int == len(fixed_tuple)
    elif kind in {SymbolicHintKind.SET, SymbolicHintKind.FROZENSET}:
        type_branch = sym_val.is_set
    elif kind == SymbolicHintKind.DICT:
        type_branch = sym_val.is_dict
    elif kind == SymbolicHintKind.OBJECT:
        type_branch = sym_val.is_obj

    if type_branch is None:
        return cast("SymbolicCreatedValue", sym_val), constraint

    nullable_constraint = z3.And(
        constraint,
        z3.Or(sym_val.is_none, z3.And(type_branch, extra_constraint)),
    )
    return cast("SymbolicCreatedValue", sym_val), nullable_constraint
