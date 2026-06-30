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

"""Source-line resolution for active execution instruction streams."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.bytecode import get_position_line, get_starts_line

if TYPE_CHECKING:
    import dis

    from pysymex._internal.execution.session.state.core import ExecutionSession


def resolve_line_number(
    *,
    session: ExecutionSession,
    pc: int,
    active_instructions: list[dis.Instruction],
) -> int | None:
    """Resolve a source line for a program counter in the active instruction stream."""
    if active_instructions is session.instructions:
        return session.pc_to_line.get(pc)
    for index in range(min(pc, len(active_instructions) - 1), -1, -1):
        instr = active_instructions[index]
        if (line := get_position_line(instr)) is not None:
            return line
        if (line := get_starts_line(instr)) is not None:
            return line
    return None
