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

"""``GET_LEN`` stack semantics for match and sequence opcodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.capabilities import length_expr
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.match.pattern_ops import MatchPatternOps

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_get_len(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Push a symbolic length for the TOS value used by ``MATCH_*`` and sequences.

    CPython stack effect: ``TOS -> TOS1`` (replaces subject with ``len(subject)``).
    Resolves pattern subjects via :meth:`MatchPatternOps.subject`; uses container
    ``z3_len`` for modeled lists/dicts/strings, concrete ``len`` for ``Sized``, or a
    fresh ``Int`` symbol otherwise. Always adds ``length >= 0`` to the path.

    Side Effects:
        Mutates stack in place on the continuing path; advances PC by one.

    Limitations:
        Unknown container kinds get an unconstrained length symbol without tying it
        to element count.
    """
    if state.stack:
        value = MatchPatternOps.subject(state.peek(), state)
        length = length_expr(value)
        if length is None:
            length = z3.Int(f"len_{state.pc}")
        result = SymbolicValue(
            _name=f"len_{state.pc}",
            z3_int=length,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )
        state = state.push(result)
        state = state.add_constraint(length >= 0)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
