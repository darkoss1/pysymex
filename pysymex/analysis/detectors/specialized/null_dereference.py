# pysymex: Python Symbolic Execution & Formal Verification
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

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors.base import DisInstruction, IsSatFn, Issue
from pysymex.analysis.detectors.runtime.none_dereference import (
    NoneDereferenceDetector as RuntimeNoneDereferenceDetector,
    normalize_attr_name,
    pure_check_none_deref,
)

if TYPE_CHECKING:
    from pysymex.core.state import VMState

_normalize_attr_name = normalize_attr_name


def pure_check_null_deref(
    top: object,
    opname: str,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn,
    *,
    attr_name: object | None = None,
    skip_names: frozenset[str] | set[str] = frozenset(),
    skip_prefixes: tuple[str, ...] = (),
) -> Issue | None:
    """Pure check for None dereference that delegates to runtime detection logic."""
    if opname not in {"LOAD_ATTR", "LOAD_METHOD", "STORE_ATTR", "BINARY_SUBSCR"}:
        return None
    normalized_attr_name = (
        "__getitem__" if opname == "BINARY_SUBSCR" else _normalize_attr_name(attr_name)
    )
    if not normalized_attr_name:
        return None
    return pure_check_none_deref(
        obj=top,
        attr_name=normalized_attr_name,
        path_constraints=path_constraints,
        pc=pc,
        skip_names=skip_names,
        skip_prefixes=skip_prefixes,
        is_satisfiable_fn=is_satisfiable_fn,
    )


class NullDereferenceDetector(RuntimeNoneDereferenceDetector):
    """Specialized None dereference detector with optional subscript coverage."""

    name = "null-dereference"
    description = "Detects potential None dereference"
    relevant_opcodes = frozenset({"LOAD_ATTR", "LOAD_METHOD", "STORE_ATTR", "BINARY_SUBSCR"})

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check for None dereference on attribute/method/subscript operations."""
        if instruction.opname not in self.relevant_opcodes or len(state.stack) < 1:
            return None
        target_obj = state.stack[-1]
        if instruction.opname == "BINARY_SUBSCR":
            if len(state.stack) < 2:
                return None
            target_obj = state.stack[-2]
        return pure_check_null_deref(
            target_obj,
            instruction.opname,
            list(state.path_constraints),
            state.pc,
            _solver_check,
            attr_name=instruction.argval,
            skip_names=self.SKIP_NAMES,
            skip_prefixes=self.INTERNAL_PREFIXES,
        )
