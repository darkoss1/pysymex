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

from collections.abc import Hashable
from dataclasses import replace
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
    from pysymex._internal.core.state.record import VMState

from pysymex._internal.analysis.detectors.calls import extract_argc, resolve_call_target_name
from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_feasibility_evidence,
)
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.core.bytecode import DIRECT_CALL_OPCODES
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.checks import is_type_subscription
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


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
        return ConstraintValues.string(str(key)), []
    return None, []


def _resolve_container(value: object, state: VMState) -> object:
    """Resolve symbolic object indirection from VM memory when available."""
    from pysymex._internal.core.types.containers.objects import SymbolicObject

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
    issue = issue_from_feasibility_evidence(
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
    if issue is None or issue.model is not None or issue.counterexample is not None:
        return issue

    partial_counterexample = _partial_input_counterexample_from_constraints(constraints)
    if not partial_counterexample:
        return issue
    return replace(issue, counterexample=partial_counterexample)


def _partial_input_counterexample_from_constraints(
    constraints: list[z3.BoolRef],
) -> dict[str, object]:
    """Extract concrete user-input equalities from an otherwise inconclusive path.

    Detector feasibility can be inconclusive on large symbolic containers even when the
    branch condition that reaches the lookup is already concrete. Preserve those input
    bindings as low-confidence counterexample context without pretending the entire path
    was model-backed.
    """
    counterexample: dict[str, object] = {}
    for constraint in constraints:
        equality = _constraint_const_literal_equality(constraint)
        if equality is None:
            continue
        name, value = equality
        base_name = _counterexample_base_name(name)
        if base_name is None or base_name in counterexample:
            continue
        counterexample[base_name] = value
    return counterexample


def _constraint_const_literal_equality(
    constraint: z3.BoolRef,
) -> tuple[str, object] | None:
    """Return ``(const_name, literal_value)`` for simple equality constraints."""
    if not z3.is_app(constraint) or constraint.decl().kind() != z3.Z3_OP_EQ:
        return None
    if constraint.num_args() != 2:
        return None
    left = constraint.arg(0)
    right = constraint.arg(1)
    return _const_literal_pair(left, right) or _const_literal_pair(right, left)


def _const_literal_pair(name_expr: z3.ExprRef, value_expr: z3.ExprRef) -> tuple[str, object] | None:
    """Return a concrete equality pair when ``name_expr`` is an uninterpreted const."""
    if not z3.is_const(name_expr):
        return None
    name = name_expr.decl().name()
    if name.startswith("_"):
        return None
    if isinstance(value_expr, z3.IntNumRef):
        return name, value_expr.as_long()
    if z3.is_true(value_expr):
        return name, True
    if z3.is_false(value_expr):
        return name, False
    if isinstance(value_expr, z3.SeqRef) and z3.is_string_value(value_expr):
        return name, value_expr.as_string()
    return None


def _counterexample_base_name(name: str) -> str | None:
    """Map internal symbolic input fields back to the user-facing argument name."""
    base_name = name
    for suffix in ("_is_none", "_is_int", "_is_bool", "_is_str", "_int", "_bool", "_str"):
        if base_name.endswith(suffix):
            base_name = base_name[: -len(suffix)]
            break
    if not base_name or base_name.startswith("_"):
        return None
    if base_name in {"Int", "Bool", "String"}:
        return None
    if "[" in base_name or "]" in base_name or "." in base_name:
        return None
    return base_name


class KeyErrorDetector(Detector):
    """Detects subscript access on a ``SymbolicDict`` with a possibly-missing key."""

    name = "key-error"
    description = "Detects missing dictionary keys"
    issue_kind = IssueKind.KEY_ERROR
    relevant_opcodes = DIRECT_CALL_OPCODES | frozenset(("BINARY_SUBSCR", "DELETE_SUBSCR"))

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check for missing-key access on symbolic dicts."""
        return _check_key_error(self, state, instruction, _solver_check)


def _check_key_error(
    detector: KeyErrorDetector,
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
) -> Issue | None:
    """Check one subscript/delete/pop operation for missing-key evidence."""
    target = _key_lookup_target(detector, state, instruction)
    if target is None:
        return None
    key, container = target

    if is_type_subscription(container):
        return None
    if isinstance(container, dict):
        concrete_container = cast("dict[object, object]", container)
        return _concrete_dict_key_issue(concrete_container, key, state, solver_check)
    if not isinstance(container, SymbolicDict):
        return None
    if instruction.opname == "BINARY_SUBSCR" and getattr(container, "_has_default_factory", False):
        return None

    concrete_backed_issue = _concrete_backed_symbolic_dict_key_issue(
        container,
        key,
        state,
        solver_check,
    )
    if concrete_backed_issue is not None:
        return concrete_backed_issue
    return _symbolic_dict_key_issue(container, key, state, solver_check)


def _key_lookup_target(
    detector: KeyErrorDetector,
    state: VMState,
    instruction: dis.Instruction,
) -> tuple[object, object] | None:
    """Return lookup key and resolved container for supported key-error opcodes."""
    if instruction.opname in {"BINARY_SUBSCR", "DELETE_SUBSCR"}:
        if len(state.stack) < 2:
            return None
        return state.stack[-1], _resolve_container(state.stack[-2], state)

    if instruction.opname not in detector.relevant_opcodes:
        return None
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
    return state.stack[-argc], _resolve_container(state.stack[-(argc + 1)], state)


def _concrete_dict_key_issue(
    container: dict[object, object],
    key: object,
    state: VMState,
    solver_check: IsSatFn,
) -> Issue | None:
    """Build missing-key evidence for concrete dictionaries."""
    concrete_key = _extract_concrete_key(key)
    if not isinstance(concrete_key, Hashable):
        return None
    try:
        key_missing = concrete_key not in container
    except TypeError:
        return None
    if not key_missing:
        return None
    return _key_issue_from_constraints(
        state=state,
        constraints=list(state.path_constraints),
        is_satisfiable_fn=solver_check,
        message=f"Possible KeyError: concrete dict missing key {concrete_key!r}",
    )


def _concrete_backed_symbolic_dict_key_issue(
    container: SymbolicDict,
    key: object,
    state: VMState,
    solver_check: IsSatFn,
) -> Issue | None:
    """Build missing-key evidence for SymbolicDict values with concrete backing."""
    concrete_items = getattr(container, "_concrete_items", None)
    if not isinstance(concrete_items, dict):
        return None

    concrete_presence = container.concrete_key_presence_condition(key)
    if concrete_presence is not None:
        concrete_presence = simplify_expr(concrete_presence)
        if z3.is_true(concrete_presence):
            return None
        return _key_issue_from_constraints(
            state=state,
            constraints=[*state.path_constraints, z3.Not(concrete_presence)],
            is_satisfiable_fn=solver_check,
            message="Possible KeyError: subscript key may be missing",
        )

    concrete_key = _extract_concrete_key(key)
    if concrete_key is None:
        return None
    if not isinstance(concrete_key, Hashable):
        return None
    if concrete_key in concrete_items:
        return None
    return _key_issue_from_constraints(
        state=state,
        constraints=list(state.path_constraints),
        is_satisfiable_fn=solver_check,
        message=f"Possible KeyError: concrete dict missing key {concrete_key!r}",
    )


def _symbolic_dict_key_issue(
    container: SymbolicDict,
    key: object,
    state: VMState,
    solver_check: IsSatFn,
) -> Issue | None:
    """Build missing-key evidence for general symbolic dictionary lookups."""
    key_expr, key_constraints = _symbolic_key_constraints(key)
    if key_expr is None:
        return None
    concrete_key = _extract_concrete_key(key)
    if isinstance(concrete_key, (str, int, float, bool)):
        key_const = ConstraintValues.string(str(concrete_key))
        present = simplify_expr(z3.Select(container.known_keys, key_const))
        if z3.is_true(present):
            return None
        if z3.is_false(present):
            return _key_issue_from_constraints(
                state=state,
                constraints=[*state.path_constraints, *key_constraints],
                is_satisfiable_fn=solver_check,
                message="Possible KeyError: subscript key may be missing",
            )

    return _key_issue_from_constraints(
        state=state,
        constraints=[
            *state.path_constraints,
            *key_constraints,
            z3.Not(z3.Select(container.known_keys, key_expr)),
        ],
        is_satisfiable_fn=solver_check,
        message="Possible KeyError: subscript key may be missing",
    )
