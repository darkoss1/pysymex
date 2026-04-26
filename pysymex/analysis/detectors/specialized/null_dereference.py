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

import z3
from typing import TYPE_CHECKING

from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, DisInstruction, IsSatFn
from pysymex.core.types.havoc import is_havoc

if TYPE_CHECKING:
    from pysymex.core.state import VMState


def pure_check_null_deref(
    top: object,
    opname: str,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn,
) -> Issue | None:
    """Pure: check whether *top* could be None for the given *opname*."""
    from pysymex.core.types.scalars import SymbolicNone, SymbolicValue

    if is_havoc(top):
        return None
    if isinstance(top, SymbolicNone):
        return Issue(
            kind=IssueKind.NULL_DEREFERENCE,
            message=f"Definite None dereference at {opname}",
            pc=pc,
        )
    if isinstance(top, SymbolicValue):
        none_check = [*path_constraints, top.is_none]
        if is_satisfiable_fn(none_check):
            must_be_none = not is_satisfiable_fn([*path_constraints, z3.Not(top.is_none)])
            is_unconstrained = (
                z3.is_const(top.is_none) and top.is_none.decl().kind() == z3.Z3_OP_UNINTERPRETED
            )
            if must_be_none or not is_unconstrained:
                from pysymex.core.solver.engine import get_model

                return Issue(
                    kind=IssueKind.NULL_DEREFERENCE,
                    message=f"Possible None dereference at {opname}",
                    constraints=none_check,
                    model=get_model(none_check),
                    pc=pc,
                )
    return None


class NullDereferenceDetector(Detector):
    """Detects potential null/None dereference on attribute access and subscript.

    Checks ``LOAD_ATTR``, ``LOAD_METHOD``, and ``BINARY_SUBSCR`` opcodes
    to determine if the top-of-stack value could be ``None``.
    """

    name = "null-dereference"
    description = "Detects potential None dereference"
    issue_kind = IssueKind.NULL_DEREFERENCE
    relevant_opcodes = frozenset({"LOAD_ATTR", "LOAD_METHOD", "BINARY_SUBSCR"})

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for None dereference at attribute access or method calls."""
        if instruction.opname not in ("LOAD_ATTR", "LOAD_METHOD", "BINARY_SUBSCR"):
            return None
        if not state.stack:
            return None
        return pure_check_null_deref(
            state.peek(),
            instruction.opname,
            list(state.path_constraints),
            state.pc,
            is_satisfiable_fn,
        )
