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

"""Memory-cell merge helpers for symbolic state joins."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.memory.cow.dicts import CowDict
from pysymex._internal.execution.strategies.merger.merge_guards import MergeGuards
from pysymex._internal.execution.strategies.merger.symbolic.values import SymbolicValueMerges
from pysymex._internal.typing.protocols import StackValue

if TYPE_CHECKING:
    from collections.abc import Mapping

    import z3

    from pysymex._internal.core.memory.cow.dicts import CowDictMutation
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.strategies.merger.symbolic.regions.types import ValuesEqual


def merge_memory(
    merged: VMState,
    state1: VMState,
    state2: VMState,
    condition: z3.BoolRef,
    values_equal: ValuesEqual,
) -> bool:
    """Merge memory cells into ``merged`` under ``condition``."""
    all_addrs = set(state1.memory.keys()) | set(state2.memory.keys())
    merged.memory = CowDict[int, StackValue]()
    with merged.memory.mutate() as mut:
        for addr in all_addrs:
            cell1 = state1.memory.get(addr)
            cell2 = state2.memory.get(addr)
            dict1 = MergeGuards.as_mapping(cell1)
            dict2 = MergeGuards.as_mapping(cell2)
            if dict1 is None or dict2 is None:
                if not _merge_non_mapping_memory_cell(
                    mut,
                    addr,
                    cell1,
                    cell2,
                    condition,
                    values_equal,
                ):
                    return False
                continue

            merged_dict = _merge_memory_dict(dict1, dict2, condition, values_equal)
            if merged_dict is None:
                return False
            mut[addr] = dict(merged_dict)
    return True


def _merge_non_mapping_memory_cell(
    mut: CowDictMutation[int, StackValue],
    addr: int,
    cell1: StackValue | None,
    cell2: StackValue | None,
    condition: z3.BoolRef,
    values_equal: ValuesEqual,
) -> bool:
    if cell1 is not None and cell2 is not None:
        if values_equal(cell1, cell2):
            mut[addr] = cell1
            return True
        merged_cell = SymbolicValueMerges.pair(cell1, cell2, condition)
        if merged_cell is None:
            return False
        mut[addr] = merged_cell
    elif cell1 is not None:
        mut[addr] = cell1
    elif cell2 is not None:
        mut[addr] = cell2
    return True


def _merge_memory_dict(
    dict1: Mapping[str, StackValue],
    dict2: Mapping[str, StackValue],
    condition: z3.BoolRef,
    values_equal: ValuesEqual,
) -> dict[str, StackValue] | None:
    merged_dict: dict[str, StackValue] = {}
    all_attrs = set(dict1.keys()) | set(dict2.keys())
    for attr in all_attrs:
        value1 = dict1.get(attr)
        value2 = dict2.get(attr)
        if value1 is not None and value2 is not None:
            if value1 is value2:
                merged_dict[attr] = value1
                continue
            if values_equal(value1, value2):
                merged_dict[attr] = value1
                continue
            merged_value = SymbolicValueMerges.pair(value1, value2, condition)
            if merged_value is None:
                return None
            merged_dict[attr] = merged_value
        elif value1 is not None:
            merged_dict[attr] = value1
        elif value2 is not None:
            merged_dict[attr] = value2
    return merged_dict
