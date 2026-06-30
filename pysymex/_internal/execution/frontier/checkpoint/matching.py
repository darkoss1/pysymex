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

"""Exact checkpoint root comparisons for POLAR frontier dominance gates."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex._internal.core.state.branches import BranchChain
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import LoopCounterKey


def z3_constraint_multisets_match(
    left: tuple[z3.BoolRef, ...],
    right: tuple[z3.BoolRef, ...],
) -> bool:
    """Return whether both constraint collections contain the same exact ASTs."""
    if len(left) != len(right):
        return False
    matched = [False] * len(right)
    for left_constraint in left:
        found = False
        for index, right_constraint in enumerate(right):
            if not matched[index] and z3.eq(left_constraint, right_constraint):
                matched[index] = True
                found = True
                break
        if not found:
            return False
    return True


def value_matches(left: object, right: object) -> bool:
    """Return whether two checkpoint values are safe exact matches."""
    if left is right:
        return True
    if type(left) is not type(right):
        return False
    if isinstance(left, (bool, int, float, str, bytes, type(None))):
        return left == right
    return False


def values_match(left: tuple[object, ...], right: tuple[object, ...]) -> bool:
    """Return whether both value sequences have exact checkpoint-visible roots."""
    return len(left) == len(right) and all(
        value_matches(left_value, right_value)
        for left_value, right_value in zip(left, right, strict=True)
    )


def named_values_match(
    left: tuple[tuple[str, object], ...],
    right: tuple[tuple[str, object], ...],
) -> bool:
    """Return whether named value tuples match by key and exact value root."""
    return len(left) == len(right) and all(
        left_name == right_name and value_matches(left_value, right_value)
        for (left_name, left_value), (right_name, right_value) in zip(left, right, strict=True)
    )


def memory_values_match(
    left: tuple[tuple[int, object], ...],
    right: tuple[tuple[int, object], ...],
) -> bool:
    """Return whether memory cells match by address and exact value root."""
    return len(left) == len(right) and all(
        left_address == right_address and value_matches(left_value, right_value)
        for (left_address, left_value), (right_address, right_value) in zip(
            left,
            right,
            strict=True,
        )
    )


def objects_match(left: tuple[object, ...], right: tuple[object, ...]) -> bool:
    """Return whether complex metadata roots are the same objects or simple equals."""
    return values_match(left, right)


def objects_match_optional(
    left: tuple[object, ...] | None,
    right: tuple[object, ...] | None,
) -> bool:
    """Return whether optional metadata root tuples match exactly."""
    if left is None or right is None:
        return left is right
    return objects_match(left, right)


def branch_traces_match(left: BranchChain, right: BranchChain) -> bool:
    """Return whether two branch traces contain the same exact decisions."""
    left_records = left.to_list()
    right_records = right.to_list()
    return len(left_records) == len(right_records) and all(
        left_record.pc == right_record.pc
        and left_record.taken == right_record.taken
        and z3.eq(left_record.condition, right_record.condition)
        for left_record, right_record in zip(left_records, right_records, strict=True)
    )


def previous_loop_states_match(
    left: tuple[tuple[LoopCounterKey, VMState], ...],
    right: tuple[tuple[LoopCounterKey, VMState], ...],
) -> bool:
    """Return whether previous loop-state references match exactly."""
    return len(left) == len(right) and all(
        left_key == right_key and left_state is right_state
        for (left_key, left_state), (right_key, right_state) in zip(left, right, strict=True)
    )


def awaitable_results_match(
    left: tuple[tuple[int, object], ...],
    right: tuple[tuple[int, object], ...],
) -> bool:
    """Return whether awaitable result roots match by ID and exact value."""
    return len(left) == len(right) and all(
        left_id == right_id and value_matches(left_value, right_value)
        for (left_id, left_value), (right_id, right_value) in zip(left, right, strict=True)
    )
