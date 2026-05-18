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
from pysymex.core.types import (
    SymbolicNone,
    SymbolicValue,
)
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn, GetModelFn


def normalize_attr_name(attr_name: object) -> str:
    """Normalize bytecode argval into a usable attribute name string."""
    if isinstance(attr_name, str):
        return attr_name
    if attr_name is None:
        return ""
    return str(attr_name)


_normalize_attr_name = normalize_attr_name


def _none_has_attr(attr_name: str) -> bool:
    """Return True when Python ``None`` supports ``attr_name``."""
    if not attr_name:
        return False
    return hasattr(None, attr_name)


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

    normalized_attr_name = _normalize_attr_name(attr_name)
    if not normalized_attr_name:
        return None

    if is_havoc(obj):
        return None

    if obj is None or isinstance(obj, SymbolicNone):
        if _none_has_attr(normalized_attr_name):
            return None
        if not is_satisfiable_fn(path_constraints):
            return None
        return Issue(
            kind=IssueKind.NULL_DEREFERENCE,
            message=f"Attribute access '{normalized_attr_name}' on None",
            constraints=path_constraints,
            model=get_model_fn(path_constraints),
            pc=pc,
        )

    if isinstance(obj, SymbolicValue):
        if obj.name in skip_names:
            return None
        if any(obj.name.startswith(prefix) for prefix in skip_prefixes):
            return None
        if normalized_attr_name == "close" and obj.name.startswith("file_"):
            return None
        if _none_has_attr(normalized_attr_name):
            return None
        none_constraint = [*path_constraints, obj.is_none]
        if not is_satisfiable_fn(none_constraint):
            return None

        confidence = 1.0
        if hasattr(obj, "affinity_type") and obj.affinity_type != "NoneType":
            confidence = 0.7

        return Issue(
            kind=IssueKind.NULL_DEREFERENCE,
            message=f"'{normalized_attr_name}' access on {obj.name} which could be None",
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
    relevant_opcodes = frozenset(
        {
            "LOAD_ATTR",
            "LOAD_SUPER_ATTR",
            "LOAD_METHOD",
            "STORE_ATTR",
            "DELETE_ATTR",
            "BINARY_SUBSCR",
        }
    )
    SKIP_NAMES = {"self", "cls", "module", "builtins", "__builtins__"}
    INTERNAL_PREFIXES = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname not in self.relevant_opcodes:
            return None
        if instruction.opname == "BINARY_SUBSCR":
            if len(state.stack) < 2:
                return None
            obj = state.stack[-2]
        else:
            if len(state.stack) < 1:
                return None
            obj = state.stack[-1]

        attr_name: str = (
            "__getitem__"
            if instruction.opname == "BINARY_SUBSCR"
            else _normalize_attr_name(instruction.argval)
        )
        return pure_check_none_deref(
            obj,
            attr_name,
            list(state.path_constraints),
            state.pc,
            self.SKIP_NAMES,
            self.INTERNAL_PREFIXES,
            is_satisfiable_fn=_solver_check,
        )
