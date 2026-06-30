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

"""Retained call-frame merge helpers for symbolic state joins."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from pysymex._internal.core.state.types import wrap_cow_dict
from pysymex._internal.execution.strategies.merger.symbolic.values import SymbolicValueMerges

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.strategies.merger.symbolic.regions.types import ValuesEqual
    from pysymex._internal.typing.protocols import StackValue


def merge_call_stack(
    merged: VMState,
    state1: VMState,
    state2: VMState,
    condition: z3.BoolRef,
    values_equal: ValuesEqual,
) -> bool:
    """Merge retained call-frame locals into ``merged`` under ``condition``."""
    if len(state1.call_stack) != len(state2.call_stack):
        return not state1.call_stack and not state2.call_stack

    merged_call_stack: list[CallFrame] = []
    for frame1, frame2 in zip(state1.call_stack, state2.call_stack, strict=False):
        if frame1.function_name != frame2.function_name or frame1.return_pc != frame2.return_pc:
            return False

        frame_locals_seed: dict[str, StackValue] = {}
        merged_frame_locals = wrap_cow_dict(frame_locals_seed)
        all_keys = set(frame1.local_vars.keys()) | set(frame2.local_vars.keys())
        for key in all_keys:
            value1 = frame1.local_vars.get(key)
            value2 = frame2.local_vars.get(key)
            if value1 is not None and value2 is not None:
                if values_equal(value1, value2):
                    merged_frame_locals[key] = value1
                    continue
                merged_value = SymbolicValueMerges.pair(value1, value2, condition)
                if merged_value is None:
                    return False
                merged_frame_locals[key] = merged_value
            else:
                merged_frame_locals[key] = value1 if value1 is not None else value2

        merged_call_stack.append(replace(frame1, local_vars=merged_frame_locals))
    merged.call_stack = merged_call_stack
    return True
