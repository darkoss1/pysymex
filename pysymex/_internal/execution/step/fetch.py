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

"""Instruction selection for one-instruction execution steps."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


def fetch_instruction(
    state: VMState,
    root_instructions: list[dis.Instruction],
) -> tuple[dis.Instruction | None, list[dis.Instruction]]:
    """Select the active instruction list and return the state's current instruction."""
    current = state.current_instructions
    if current is not None:
        if not current or isinstance(current[0], dis.Instruction):
            active_instructions = cast("list[dis.Instruction]", current)
        else:
            active_instructions = root_instructions
    else:
        active_instructions = root_instructions
    if state.pc >= len(active_instructions):
        return None, active_instructions
    return active_instructions[state.pc], active_instructions
