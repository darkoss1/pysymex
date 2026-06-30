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

"""Well-founded recurrence checks for interprocedural recursion."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.loop.bounds.finite import (
    finite_countdown_value_remaining_steps,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.calls.interprocedural.targets import InterproceduralTarget


def recursive_call_requires_summary(
    state: VMState,
    target: InterproceduralTarget,
    caller_offset: int,
) -> bool:
    """Return whether an active recursive call lacks a proven finite descent."""
    for frame in reversed(state.call_stack):
        if frame.function_code is not target.func_code or frame.caller_offset != caller_offset:
            continue
        previous_args = tuple(value for _name, value in frame.argument_aliases)
        if not previous_args or len(previous_args) != len(target.args):
            return True
        return not any(
            finite_countdown_value_remaining_steps(
                previous,
                current,
                state.path_constraints,
            )
            is not None
            for previous, current in zip(previous_args, target.args, strict=True)
        )
    return False
