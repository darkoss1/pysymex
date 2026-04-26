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

import dis
import z3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.types.havoc import is_havoc
from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.types.scalars import (
    SymbolicNone,
    SymbolicValue,
)
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn, GetModelFn


def pure_check_none_deref(
    obj: object,
    attr_name: str,
    path_constraints: list[z3.BoolRef],
    pc: int,
    skip_names: frozenset[str] | set[str] = frozenset(),
    skip_prefixes: tuple[str, ...] = (),
    is_satisfiable_fn: IsSatFn = is_satisfiable,
    get_model_fn: GetModelFn = get_model,
) -> Issue | None:
    """Pure: check if *obj* could be None when attribute *attr_name* is accessed."""

    if is_havoc(obj):
        return None
    if isinstance(obj, SymbolicNone):
        return Issue(
            kind=IssueKind.NULL_DEREFERENCE,
            message=f"Attribute access '{attr_name}' on None",
            constraints=path_constraints,
            pc=pc,
        )
    if isinstance(obj, SymbolicValue):
        if obj.name in skip_names:
            return None
        if any(obj.name.startswith(prefix) for prefix in skip_prefixes):
            return None
        if hasattr(obj, "is_none"):
            none_constraint = [*path_constraints, obj.is_none]
            if is_satisfiable_fn(none_constraint):
                confidence = 1.0
                if is_havoc(obj):
                    confidence = 0.5
                elif hasattr(obj, "affinity_type") and obj.affinity_type == "NoneType":
                    confidence = 1.0
                elif hasattr(obj, "affinity_type"):
                    confidence = 0.7

                return Issue(
                    kind=IssueKind.NULL_DEREFERENCE,
                    message=f"'{attr_name}' access on {obj.name} which could be None",
                    constraints=none_constraint,
                    model=get_model_fn(none_constraint),
                    pc=pc,
                    confidence=confidence,
                )
    return None


class NoneDereferenceDetector(Detector):
    """
    Detects attribute access or method calls on potentially None values.
    NOTE: This detector may produce false positives for class instance
    attributes accessed via 'self', as symbolic execution doesn't fully
    model Python's object initialization guarantees.
    """

    name = "none-dereference"
    description = "Detects attribute access on potentially None values"
    issue_kind = IssueKind.NULL_DEREFERENCE
    relevant_opcodes = frozenset({"LOAD_ATTR", "LOAD_METHOD", "STORE_ATTR"})
    SKIP_NAMES = {"self", "cls", "module", "builtins", "__builtins__"}
    INTERNAL_PREFIXES = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname not in ("LOAD_ATTR", "LOAD_METHOD", "STORE_ATTR"):
            return None
        if len(state.stack) < 1:
            return None
        return pure_check_none_deref(
            state.stack[-1],
            instruction.argval,
            list(state.path_constraints),
            state.pc,
            self.SKIP_NAMES,
            self.INTERNAL_PREFIXES,
        )
