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

"""Pairwise symbolic value merging for state-merge phi nodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.affinity import LENGTH_AFFINITIES
from pysymex._internal.core.types.capabilities import symbolic_affinity
from pysymex._internal.execution.strategies.merger.merge_guards import MergeGuards

if TYPE_CHECKING:
    import z3

    from pysymex._internal.typing.protocols import StackValue


def _pair(
    left: StackValue,
    right: StackValue,
    merge_condition: z3.BoolRef,
) -> StackValue | None:
    """Return a conditional merge of two stack values, or ``None`` if unsupported."""
    from pysymex._internal.core.types.containers.iterators import SymbolicIterator
    from pysymex._internal.core.types.scalars.values import SymbolicValue

    if isinstance(left, SymbolicIterator) or isinstance(right, SymbolicIterator):
        return None

    left_is_container = symbolic_affinity(left) in LENGTH_AFFINITIES
    right_is_container = symbolic_affinity(right) in LENGTH_AFFINITIES
    if left_is_container != right_is_container:
        return None
    if left_is_container and right_is_container and type(left) is not type(right):
        return None

    left_symbolic: object = (
        left if MergeGuards.is_symbolic(left) else SymbolicValue.from_const(left)
    )
    right_symbolic: object = (
        right if MergeGuards.is_symbolic(right) else SymbolicValue.from_const(right)
    )
    try:
        if not MergeGuards.is_mergeable(left_symbolic):
            return None
        merged_obj = left_symbolic.conditional_merge(right_symbolic, merge_condition)
        if not MergeGuards.is_stack_value(merged_obj):
            return None
        return merged_obj
    except TypeError:
        return None


class SymbolicValueMerges:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    pair = staticmethod(_pair)
