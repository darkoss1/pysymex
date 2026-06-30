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

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.runtime.indexing.bounds.core import (
    pure_check_index_bounds,
)
from pysymex._internal.analysis.detectors.runtime.indexing.patterns import IndexErrorPatternMixin
from pysymex._internal.analysis.detectors.runtime.indexing.targets import (
    CALL_OPCODES,
    has_precise_index_bounds,
    index_access_target,
    resolve_memory_object,
)
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState


class IndexErrorDetector(IndexErrorPatternMixin, Detector):
    """Detect out-of-bounds sequence accesses via symbolic bounds analysis.

    Bug class:
        ``IndexError`` — a list, tuple, string, or sequence subscript whose
        index is provably (or likely) out of bounds under path constraints.

    Evidence:
        The constraint ``index < -len`` or ``index >= len`` is satisfiable
        under current path constraints (via :func:`pure_check_index_bounds`).
        Unknown container lengths remain inconclusive instead of using a numeric size heuristic.

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
    relevant_opcodes = CALL_OPCODES | frozenset(("BINARY_SUBSCR", "DELETE_SUBSCR"))

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
        return _check_index_error(
            state,
            instruction,
            _solver_check,
            is_type_subscription_pattern=self._is_type_subscription_pattern,
            is_likely_dict_access=self._is_likely_dict_access,
        )


def _check_index_error(
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
    *,
    is_type_subscription_pattern: Callable[[object, object], bool],
    is_likely_dict_access: Callable[[object, object], bool],
) -> Issue | None:
    """Inspect an instruction for sequence IndexError evidence."""
    target = index_access_target(state, instruction, solver_check)
    if target is None:
        return None
    if isinstance(target, Issue):
        return target
    container, index = target
    container = resolve_memory_object(state, container)

    bounds_issue = pure_check_index_bounds(
        container,
        index,
        list(state.path_constraints),
        state.pc,
        is_satisfiable_fn=solver_check,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
    )
    if bounds_issue is not None:
        return bounds_issue

    if not isinstance(index, SymbolicValue):
        return None
    if is_type_subscription_pattern(container, index):
        return None
    if is_likely_dict_access(container, index):
        return None
    if has_precise_index_bounds(container):
        return None
    return None
