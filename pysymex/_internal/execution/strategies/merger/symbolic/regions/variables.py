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

"""Local/global variable and operand-stack merge helpers for symbolic state joins."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.strategies.merger.symbolic.values import SymbolicValueMerges

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.strategies.merger.symbolic.regions.types import ValuesEqual
    from pysymex._internal.typing.protocols import StackValue


def merge_local_vars(
    merged: VMState,
    state1: VMState,
    state2: VMState,
    condition: z3.BoolRef,
    values_equal: ValuesEqual,
) -> bool:
    """Merge local variables into ``merged`` under ``condition``."""
    with merged.local_vars.mutate() as mut:
        for name in state1.local_vars:
            val1 = state1.local_vars[name]
            val2 = state2.local_vars[name]
            if values_equal(val1, val2):
                mut[name] = val1
                continue

            merged_value = SymbolicValueMerges.pair(val1, val2, condition)
            if merged_value is None:
                return False
            mut[name] = merged_value
    return True


def merge_global_vars(
    merged: VMState,
    state1: VMState,
    state2: VMState,
    condition: z3.BoolRef,
    values_equal: ValuesEqual,
) -> bool:
    """Merge global variables into ``merged`` under ``condition``."""
    all_global_keys = set(state1.global_vars.keys()) | set(state2.global_vars.keys())
    with merged.global_vars.mutate() as mut:
        for name in all_global_keys:
            val1 = state1.global_vars.get(name)
            val2 = state2.global_vars.get(name)
            if val1 is not None and val2 is not None:
                if values_equal(val1, val2):
                    mut[name] = val1
                    continue
                merged_value = SymbolicValueMerges.pair(val1, val2, condition)
                if merged_value is None:
                    return False
                mut[name] = merged_value
            elif val1 is not None:
                mut[name] = val1
            elif val2 is not None:
                mut[name] = val2
    return True


def merge_stack(
    merged: VMState,
    state1: VMState,
    state2: VMState,
    condition: z3.BoolRef,
    values_equal: ValuesEqual,
) -> bool:
    """Merge stack entries into ``merged`` under ``condition``."""
    merged_stack: list[StackValue] = []
    for val1, val2 in zip(state1.stack, state2.stack, strict=False):
        if values_equal(val1, val2):
            merged_stack.append(val1)
            continue
        merged_value = SymbolicValueMerges.pair(val1, val2, condition)
        if merged_value is None:
            return False
        merged_stack.append(merged_value)
    merged.stack = merged_stack
    return True
