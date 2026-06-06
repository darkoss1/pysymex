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

"""Detect index-error bugs via symbolic bounds analysis."""

from __future__ import annotations

import dis
from collections.abc import Iterable
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors.calls import extract_argc, resolve_call_target_name
from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.types import IsSatFn, Issue, IssueKind
from pysymex.analysis.detectors.feasibility import get_model_if_satisfiable
from pysymex.analysis.detectors.runtime.index_error.bounds import (
    _unwrap_symbolic_sequence,
    pure_check_index_bounds,
)
from pysymex.analysis.detectors.runtime.index_error.patterns import IndexErrorPatternMixin
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.containers.sequences import SymbolicTuple
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.typing import is_list_of_objects, is_tuple_of_objects

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

CALL_OPCODES = frozenset({"CALL", "CALL_FUNCTION", "CALL_METHOD"})


class IndexErrorDetector(IndexErrorPatternMixin, Detector):
    """Detect out-of-bounds sequence accesses via symbolic bounds analysis.

    Bug class:
        ``IndexError`` — a list, tuple, string, or sequence subscript whose
        index is provably (or likely) out of bounds under path constraints.

    Evidence:
        The constraint ``index < -len`` or ``index >= len`` is satisfiable
        under current path constraints (via :func:`pure_check_index_bounds`).
        Falls back to an unbounded-growth check when concrete length is unknown.

    Issue kind:
        ``IssueKind.INDEX_ERROR``.

    Known false-positive conditions:
        - Generic objects not recognised as sequences return ``None`` (safe).
        - Type-subscription patterns (``list[int]``) are excluded.
        - Dict access with symbolic keys is excluded via
          :meth:`_is_likely_dict_access`.
        - Confidence is reduced to 0.5 for havoc containers/indexes.
    """

    name = "index-error"
    description = "Detects out-of-bounds indexing"
    issue_kind = IssueKind.INDEX_ERROR
    relevant_opcodes = frozenset(
        {"BINARY_SUBSCR", "DELETE_SUBSCR", "CALL", "CALL_FUNCTION", "CALL_METHOD"}
    )
    MAX_REASONABLE_SIZE = 10000

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Inspect *instruction* for a provable or likely out-of-bounds index.

        Handles ``BINARY_SUBSCR``, ``DELETE_SUBSCR``, and ``list.pop()`` via
        CALL opcodes.  Delegates to :func:`pure_check_index_bounds` first,
        then falls back to unbounded-growth checks.
        """
        container: object
        index: object
        if instruction.opname in {"BINARY_SUBSCR", "DELETE_SUBSCR"}:
            if len(state.stack) < 2:
                return None
            container = state.stack[-2]
            index = state.stack[-1]
        elif instruction.opname in CALL_OPCODES:
            argc = extract_argc(instruction)
            target_name = resolve_call_target_name(state, argc)
            if target_name is None:
                return None
            if not target_name.lower().endswith(".pop") and target_name.lower() != "pop":
                return None
            if argc == 0:
                if len(state.stack) < 2:
                    return None
                container = state.stack[-1]
                if isinstance(container, SymbolicObject) and container.address != -1:
                    mem_obj = state.memory.get(container.address)
                    if mem_obj is not None:
                        container = mem_obj
                return self._check_empty_default_pop(state, container, _solver_check)
            if argc != 1 or len(state.stack) < argc + 2:
                return None
            container = state.stack[-(argc + 1)]
            index = state.stack[-argc]
        else:
            return None
        if isinstance(container, SymbolicObject) and container.address != -1:
            mem_obj = state.memory.get(container.address)
            if mem_obj is not None:
                container = mem_obj

        bounds_issue = pure_check_index_bounds(
            container,
            index,
            list(state.path_constraints),
            state.pc,
            is_satisfiable_fn=_solver_check,
            last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
        )
        if bounds_issue is not None:
            return bounds_issue

        if not isinstance(index, SymbolicValue):
            return None
        if self._is_type_subscription_pattern(container, index):
            return None
        if self._is_likely_dict_access(container, index):
            return None
        if self._has_precise_index_bounds(container):
            return None
        return self._check_unbounded_index(state, index, _solver_check)

    def _check_empty_default_pop(
        self,
        state: VMState,
        container: object,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check whether ``container.pop()`` can raise ``IndexError`` on an empty sequence."""
        empty_condition = self._empty_pop_condition(container)
        if empty_condition is None:
            return None
        container_name, can_be_empty = empty_condition
        can_be_empty = z3.simplify(can_be_empty)
        if z3.is_false(can_be_empty):
            return None
        constraints = list(state.path_constraints)
        if not z3.is_true(can_be_empty):
            constraints.append(can_be_empty)
        model = None
        if constraints:
            model = get_model_if_satisfiable(constraints, is_satisfiable_fn)
            if model is None:
                return None
        return Issue(
            kind=IssueKind.INDEX_ERROR,
            message=f"Possible IndexError: pop from empty {container_name}",
            constraints=constraints,
            model=model,
            pc=state.pc,
        )

    @staticmethod
    def _empty_pop_condition(container: object) -> tuple[str, z3.BoolRef] | None:
        """Return the empty-sequence condition for containers that support no-arg ``pop``."""
        unwrapped = _unwrap_symbolic_sequence(container)
        if isinstance(unwrapped, SymbolicList):
            return unwrapped.name, unwrapped.z3_len == 0
        if is_list_of_objects(unwrapped):
            return "list", Z3_TRUE if len(unwrapped) == 0 else Z3_FALSE
        if isinstance(unwrapped, bytearray):
            return "bytearray", Z3_TRUE if len(unwrapped) == 0 else Z3_FALSE
        return None

    def _has_precise_index_bounds(self, container: object) -> bool:
        """Return ``True`` if the bounds check in :func:`pure_check_index_bounds` already covered *container*."""
        unwrapped = _unwrap_symbolic_sequence(container)
        return (
            isinstance(
                unwrapped,
                (SymbolicList, SymbolicTuple, SymbolicString, str, bytes, bytearray, range),
            )
            or is_list_of_objects(unwrapped)
            or is_tuple_of_objects(unwrapped)
        )

    def _check_unbounded_index(
        self,
        state: VMState,
        index: SymbolicValue,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check whether the symbolic *index* can grow unreasonably large (fallback).

        Used when the container has no known length.  Adds a constraint
        ``index >= MAX_REASONABLE_SIZE`` and checks feasibility.
        """
        concrete_index = _symbolic_value_int(index)
        if concrete_index is not None and concrete_index < self.MAX_REASONABLE_SIZE:
            return None
        if self._has_symbolic_upper_guard(state.path_constraints, index.z3_int):
            return None
        large_constraint = [
            *state.path_constraints,
            index.is_int,
            index.z3_int >= self.MAX_REASONABLE_SIZE,
        ]
        model = get_model_if_satisfiable(large_constraint, is_satisfiable_fn)
        if model is None:
            return None
        return Issue(
            kind=IssueKind.INDEX_ERROR,
            message=(
                f"Index {index.name} could be unreasonably large (>= {self.MAX_REASONABLE_SIZE})"
            ),
            constraints=large_constraint,
            model=model,
            pc=state.pc,
            confidence=0.8,
        )

    def _has_symbolic_upper_guard(
        self,
        constraints: Iterable[z3.BoolRef],
        index_expr: z3.ArithRef,
    ) -> bool:
        """Return ``True`` if any constraint acts as a symbolic upper bound on *index_expr*.

        Args:
            constraints: The active path constraint list.
            index_expr: The Z3 integer expression being indexed.
        """
        return any(self._constraint_is_symbolic_upper_guard(c, index_expr) for c in constraints)

    def _constraint_is_symbolic_upper_guard(
        self,
        constraint: z3.BoolRef,
        index_expr: z3.ArithRef,
    ) -> bool:
        """Return ``True`` if *constraint* establishes an upper bound on *index_expr*.

        Matches ``index <= expr`` or ``not (index >= expr)`` patterns where
        the bound is a non-literal symbolic expression.
        """
        simplified = z3.simplify(constraint)
        if z3.is_and(simplified):
            return any(
                self._constraint_is_symbolic_upper_guard(child, index_expr)
                for child in simplified.children()
                if isinstance(child, z3.BoolRef)
            )
        if z3.is_not(simplified):
            child = simplified.arg(0)
            kind = child.decl().kind()
            if kind in {z3.Z3_OP_GE, z3.Z3_OP_GT} and len(child.children()) == 2:
                left, right = child.children()
                return z3.eq(left, index_expr) and not _is_numeric_literal(right)
            return False
        kind = simplified.decl().kind()
        if kind in {z3.Z3_OP_LE, z3.Z3_OP_LT} and len(simplified.children()) == 2:
            left, right = simplified.children()
            return z3.eq(left, index_expr) and not _is_numeric_literal(right)
        return False


def _is_numeric_literal(expr: z3.ExprRef) -> bool:
    """Return ``True`` if *expr* is an integer, rational, or algebraic Z3 constant."""
    return z3.is_int_value(expr) or z3.is_rational_value(expr) or z3.is_algebraic_value(expr)


def _symbolic_value_int(value: SymbolicValue) -> int | None:
    """Return a concrete integer payload or simplified integer channel."""
    concrete = value.value
    if isinstance(concrete, int) and not isinstance(concrete, bool):
        return concrete
    if z3.is_int_value(value.z3_int):
        return value.z3_int.as_long()
    simplified_index = z3.simplify(value.z3_int)
    if not z3.is_int_value(simplified_index):
        return None
    return simplified_index.as_long()


__all__ = ["CALL_OPCODES", "IndexErrorDetector"]
