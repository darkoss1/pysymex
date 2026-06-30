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

"""Legacy control-side ``RAISE_VARARGS`` handler shared by version modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.opcodes.common.exceptions.raising import (
    handle_exception_raise_varargs,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


def handle_control_raise_varargs(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Delegate ``RAISE_VARARGS`` to the exception-flow SSoT.

    CPython stack effect for ``RAISE_VARARGS 1`` is ``-1``: the raised exception
    operand is consumed before handler dispatch. Exception-table routing and
    block-stack fallbacks are owned by
    :func:`pysymex._internal.execution.opcodes.common.exceptions.raising.handle_exception_raise_varargs`.

    Side Effects:
        Mutates the supplied state through the delegated exception handler.

    Limitations:
        See the exception-flow owner for cause/context and bare re-raise limits.
    """
    return handle_exception_raise_varargs(instr, state, ctx)
