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
from collections.abc import Hashable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.solver.engine import get_model
from pysymex.core.solver.constraints import simplify_expr
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types import (
    SymbolicDict,
    SymbolicString,
    SymbolicValue,
)
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn
from pysymex.analysis.detectors.runtime.division_by_zero import (
    extract_argc,
    resolve_call_target_name,
)


def _extract_concrete_key(key: object) -> object | None:
    """Extract a concrete lookup key when possible."""
    if isinstance(key, SymbolicString):
        if z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        return None
    if isinstance(key, SymbolicValue):
        if key.value is not None:
            return key.value
        if z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        return None
    return key


def _symbolic_key_constraints(key: object) -> tuple[z3.SeqRef | None, list[z3.BoolRef]]:
    """Return (key_expr, key_constraints) for SymbolicDict lookups."""
    if isinstance(key, SymbolicString):
        return key.z3_str, []
    if isinstance(key, SymbolicValue):
        return key.z3_str, [key.is_str]
    if isinstance(key, (str, int, float, bool)):
        return z3.StringVal(str(key)), []
    return None, []


def _resolve_container(value: object, state: VMState) -> object:
    """Resolve symbolic object indirection from VM memory when available."""
    from pysymex.core.types import SymbolicObject

    if isinstance(value, SymbolicObject) and value.address != -1:
        mem_obj = state.memory.get(value.address)
        if mem_obj is not None:
            return mem_obj
    return value


class KeyErrorDetector(Detector):
    """Detects subscript access on a ``SymbolicDict`` with a possibly-missing key."""

    name = "key-error"
    description = "Detects missing dictionary keys"
    issue_kind = IssueKind.KEY_ERROR
    relevant_opcodes = frozenset(
        {"BINARY_SUBSCR", "DELETE_SUBSCR", "CALL", "CALL_FUNCTION", "CALL_METHOD"}
    )

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check for missing-key access on symbolic dicts."""
        if instruction.opname in {"BINARY_SUBSCR", "DELETE_SUBSCR"}:
            if len(state.stack) < 2:
                return None
            key = state.stack[-1]
            container = _resolve_container(state.stack[-2], state)
        elif instruction.opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
            argc = extract_argc(instruction)
            target_name = resolve_call_target_name(state, argc)
            if target_name is None:
                return None
            if not target_name.lower().endswith(".pop") and target_name.lower() != "pop":
                return None
            if argc < 1 or len(state.stack) < argc + 2:
                return None
            key = state.stack[-argc]
            container = _resolve_container(state.stack[-(argc + 1)], state)
        else:
            return None

        if is_type_subscription(container):
            return None

        if isinstance(container, dict):
            concrete_key = _extract_concrete_key(key)
            if not isinstance(concrete_key, Hashable):
                return None
            try:
                key_missing = concrete_key not in container
            except TypeError:
                return None
            if not key_missing:
                return None
            constraints = list(state.path_constraints)
            if not _solver_check(constraints):
                return None
            return Issue(
                kind=IssueKind.KEY_ERROR,
                message=f"Possible KeyError: concrete dict missing key {concrete_key!r}",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )

        if not isinstance(container, SymbolicDict):
            return None

        concrete_items = getattr(container, "_concrete_items", None)
        if isinstance(concrete_items, dict):
            concrete_key = _extract_concrete_key(key)
            if concrete_key is not None:
                if not isinstance(concrete_key, Hashable):
                    return None
                if concrete_key in concrete_items:
                    return None
                constraints = list(state.path_constraints)
                if not _solver_check(constraints):
                    return None
                return Issue(
                    kind=IssueKind.KEY_ERROR,
                    message=f"Possible KeyError: concrete dict missing key {concrete_key!r}",
                    constraints=constraints,
                    model=get_model(constraints),
                    pc=state.pc,
                )

        key_expr, key_constraints = _symbolic_key_constraints(key)
        if key_expr is None:
            return None
        concrete_key = _extract_concrete_key(key)
        if isinstance(concrete_key, (str, int, float, bool)):
            key_const = z3.StringVal(str(concrete_key))
            present = simplify_expr(z3.Select(container.known_keys, key_const))
            if z3.is_true(present):
                return None
            if z3.is_false(present):
                constraints = [*state.path_constraints, *key_constraints]
                if not _solver_check(constraints):
                    return None
                return Issue(
                    kind=IssueKind.KEY_ERROR,
                    message=f"Possible KeyError: {container.name} missing key {concrete_key!r}",
                    constraints=constraints,
                    model=get_model(constraints),
                    pc=state.pc,
                )

        missing_key: list[z3.BoolRef] = [
            *state.path_constraints,
            *key_constraints,
            z3.Not(z3.Select(container.known_keys, key_expr)),
        ]

        if not _solver_check(missing_key):
            return None
        return Issue(
            kind=IssueKind.KEY_ERROR,
            message=f"Possible KeyError: {container.name} may not contain key",
            constraints=missing_key,
            model=get_model(missing_key),
            pc=state.pc,
        )
