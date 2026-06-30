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

"""None Dereference (Null Pointer) error detector module.

This module provides runtime detection for attribute accesses, method calls, or subscript
actions performed on potentially `None` objects during symbolic execution.

Bug Class Detected:
    Null Dereference / AttributeError / TypeError.

Required Evidence:
    Satisfiable path constraints extended with the constraint that the target object is None.

Issue Kinds:
    IssueKind.NULL_DEREFERENCE
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    import z3

    from pysymex._internal.core.state.record import VMState

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.types import GetModelFn, IsSatFn, Issue
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.core.solver.engine.policies import path_may_be_feasible
from pysymex._internal.core.solver.engine.queries import get_model
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.havoc import is_havoc
from pysymex._internal.core.types.scalars.values import SymbolicValue


def normalize_attr_name(attr_name: object) -> str:
    """Normalize bytecode argval into a usable attribute name string."""
    if isinstance(attr_name, str):
        return attr_name
    if attr_name is None:
        return ""
    return str(attr_name)


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
    is_satisfiable_fn: IsSatFn = path_may_be_feasible,
    get_model_fn: GetModelFn = get_model,
) -> Issue | None:
    """Determine whether *obj* can be ``None`` when *attr_name* is accessed.

    Pure function — all inputs are explicit.  Queries the solver to
    check whether the ``is_none`` constraint is satisfiable under the
    current path.

    Args:
        obj: The object being dereferenced (concrete, symbolic, or ``None``).
        attr_name: Attribute being accessed.
        path_constraints: Current path constraint list.
        pc: Bytecode offset of the access.
        skip_names: Variable names to ignore (e.g. ``self``).
        skip_prefixes: Name prefixes to ignore.
        is_satisfiable_fn: Solver satisfiability callback.
        get_model_fn: Solver model-extraction callback.

    Returns:
        An :class:`Issue` if ``None``-dereference is feasible, else ``None``.

    """
    normalized_attr_name = normalize_attr_name(attr_name)
    if not normalized_attr_name:
        return None

    if is_havoc(obj):
        return None

    if obj is None or isinstance(obj, SymbolicNoneType):
        if _none_has_attr(normalized_attr_name):
            return None
        model = get_model_if_satisfiable_result(
            path_constraints,
            is_satisfiable_fn,
            get_model_fn,
        ).model
        if model is None:
            return None
        return Issue(
            kind=IssueKind.NULL_DEREFERENCE,
            message=f"Attribute access '{normalized_attr_name}' on None",
            constraints=path_constraints,
            model=model,
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
        model = get_model_if_satisfiable_result(
            none_constraint,
            is_satisfiable_fn,
            get_model_fn,
        ).model
        if model is None:
            return None

        confidence = 1.0
        if hasattr(obj, "affinity_type") and obj.affinity_type != "none":
            confidence = 0.7

        return Issue(
            kind=IssueKind.NULL_DEREFERENCE,
            message=f"'{normalized_attr_name}' access on {obj.name} which could be None",
            constraints=none_constraint,
            model=model,
            pc=pc,
            confidence=confidence,
        )
    return None


class NoneDereferenceDetector(Detector):
    """Detect attribute access or method calls on potentially ``None`` values.

    Bug class:
        ``AttributeError`` / ``TypeError`` from attribute, method, or
        subscript access on ``None``.

    Evidence:
        Object is concrete ``None``, or a satisfiable path constraint
        extended with the ``is_none`` flag.

    Issue kind:
        ``IssueKind.NULL_DEREFERENCE``.

    Known false-positive conditions:
        May report false positives for instance attributes accessed via
        ``self``, because symbolic execution does not fully model
        ``__init__`` guarantees.  Mitigated by ``SKIP_NAMES`` and
        ``INTERNAL_PREFIXES`` filters.
    """

    name = "none-dereference"
    description = "Detects attribute access on potentially None values"
    issue_kind = IssueKind.NULL_DEREFERENCE
    relevant_opcodes = frozenset(
        (
            "LOAD_ATTR",
            "LOAD_SUPER_ATTR",
            "LOAD_METHOD",
            "STORE_ATTR",
            "DELETE_ATTR",
            "BINARY_SUBSCR",
        ),
    )
    SKIP_NAMES = {"self", "cls", "module", "builtins", "__builtins__"}
    INTERNAL_PREFIXES = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_", "super_")

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Inspect *instruction* for an attribute/subscript access on a possibly-None object.

        Reads the top-of-stack object, extracts the attribute name, and
        delegates to :func:`pure_check_none_deref`.
        """
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
            else normalize_attr_name(instruction.argval)
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
