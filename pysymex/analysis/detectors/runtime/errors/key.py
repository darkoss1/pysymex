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

"""Key Error detector module.

Detects dictionary/mapping lookups or deletions where the requested key is missing.

Bug Class Detected:
    Key Error.

Required Evidence:
    Satisfiable path constraints under which the subscript key is not present in the dictionary.

Issue Kinds:
    IssueKind.KEY_ERROR
"""

from __future__ import annotations

import dis
import z3
from collections.abc import Hashable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

from pysymex.core.solver.constraints.simplification import simplify_expr
from pysymex.core.solver.constraints.hashing import get_string_val
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.analysis.detectors.calls import extract_argc, resolve_call_target_name
from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_feasibility_evidence,
)
from pysymex.analysis.detectors.detector.types import IsSatFn, Issue, IssueKind
from pysymex.analysis.detectors.feasibility import get_model_if_satisfiable_result


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
        return get_string_val(str(key)), []
    return None, []


def _resolve_container(value: object, state: VMState) -> object:
    """Resolve symbolic object indirection from VM memory when available."""
    from pysymex.core.types.containers.objects import SymbolicObject

    if isinstance(value, SymbolicObject) and value.address != -1:
        mem_obj = state.memory.get(value.address)
        if mem_obj is not None:
            return mem_obj
    return value


def _key_issue_from_constraints(
    *,
    state: VMState,
    constraints: list[z3.BoolRef],
    is_satisfiable_fn: IsSatFn,
    message: str,
) -> Issue | None:
    """Build a KeyError issue from model-backed or inconclusive detector evidence."""
    model_result = get_model_if_satisfiable_result(constraints, is_satisfiable_fn)
    return issue_from_feasibility_evidence(
        result=model_result,
        kind=IssueKind.KEY_ERROR,
        message=message,
        constraints=constraints,
        pc=state.pc,
        path_is_inconclusive=constraints_extend_inconclusive_path(
            path_constraints=list(state.path_constraints),
            constraints=constraints,
            last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
        ),
    )


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
            if argc >= 2:
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
            return _key_issue_from_constraints(
                state=state,
                constraints=constraints,
                is_satisfiable_fn=_solver_check,
                message=f"Possible KeyError: concrete dict missing key {concrete_key!r}",
            )

        if not isinstance(container, SymbolicDict):
            return None
        if instruction.opname == "BINARY_SUBSCR" and getattr(
            container, "_has_default_factory", False
        ):
            return None

        concrete_items = getattr(container, "_concrete_items", None)
        if isinstance(concrete_items, dict):
            concrete_presence = container.concrete_key_presence_condition(key)
            if concrete_presence is not None:
                concrete_presence = simplify_expr(concrete_presence)
                if z3.is_true(concrete_presence):
                    return None
                missing_constraints = [
                    *state.path_constraints,
                    z3.Not(concrete_presence),
                ]
                return _key_issue_from_constraints(
                    state=state,
                    constraints=missing_constraints,
                    is_satisfiable_fn=_solver_check,
                    message=f"Possible KeyError: {container.name} may not contain key",
                )

            concrete_key = _extract_concrete_key(key)
            if concrete_key is not None:
                if not isinstance(concrete_key, Hashable):
                    return None
                if concrete_key in concrete_items:
                    return None
                constraints = list(state.path_constraints)
                return _key_issue_from_constraints(
                    state=state,
                    constraints=constraints,
                    is_satisfiable_fn=_solver_check,
                    message=f"Possible KeyError: concrete dict missing key {concrete_key!r}",
                )

        key_expr, key_constraints = _symbolic_key_constraints(key)
        if key_expr is None:
            return None
        concrete_key = _extract_concrete_key(key)
        if isinstance(concrete_key, (str, int, float, bool)):
            key_const = get_string_val(str(concrete_key))
            present = simplify_expr(z3.Select(container.known_keys, key_const))
            if z3.is_true(present):
                return None
            if z3.is_false(present):
                constraints = [*state.path_constraints, *key_constraints]
                return _key_issue_from_constraints(
                    state=state,
                    constraints=constraints,
                    is_satisfiable_fn=_solver_check,
                    message=f"Possible KeyError: {container.name} missing key {concrete_key!r}",
                )

        missing_key: list[z3.BoolRef] = [
            *state.path_constraints,
            *key_constraints,
            z3.Not(z3.Select(container.known_keys, key_expr)),
        ]

        return _key_issue_from_constraints(
            state=state,
            constraints=missing_key,
            is_satisfiable_fn=_solver_check,
            message=f"Possible KeyError: {container.name} may not contain key",
        )
