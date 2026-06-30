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

"""Formatting opcode wrappers for Python 3.12.

Python 3.12 uses ``FORMAT_VALUE`` for f-string formatting. This module owns
only CPython opcode registration; formatting semantics live in
:mod:`pysymex._internal.execution.opcodes.common.formatting`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.opcodes.common.formatting import handle_common_format_value

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@opcode_handler("FORMAT_VALUE")
def handle_py312_format_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Format a value for an f-string."""
    return handle_common_format_value(instr, state, ctx)
