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

"""Write-ledger recording for modeled collection mutation opcodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.effects.events import WriteEvent, WriteKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.effects.locations import WriteLocation
    from pysymex._internal.core.state.record import VMState


def record_item_write(state: VMState, location: WriteLocation, instr: dis.Instruction) -> VMState:
    """Record a successful modeled collection mutation."""
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, instr.opname),
    )
