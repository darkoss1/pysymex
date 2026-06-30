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

"""``FOR_ITER`` exit stack shaping for pre-3.12 and 3.12+ bytecode."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex._internal.core.types.base import SymbolicNoneType

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def for_iter_exit_uses_sentinel(ctx: OpcodeDispatcher, target_index: int) -> bool:
    """Return whether ``FOR_ITER`` exit needs a synthetic cleanup sentinel."""
    target = ctx.get_instruction(target_index)
    if target is not None and target.opname == "POP_TOP":
        return False
    if _is_synthetic_nop_exit(ctx, target_index):
        return True
    return _for_iter_jump_keeps_iterator()


def for_iter_exit_pops_iterator(ctx: OpcodeDispatcher, target_index: int) -> bool:
    """Return whether exhausted ``FOR_ITER`` itself removes the iterator.

    Python 3.11 has jump stack-effect ``-1`` for ``FOR_ITER`` exhaustion, including
    real loops whose jump target may be a source-line ``NOP``. Python 3.12+ keeps
    the iterator for ``END_FOR`` cleanup. Two-instruction unit-test streams may use
    ``NOP`` as a synthetic sentinel target; those retain the older sentinel-only
    abstraction.
    """
    target = ctx.get_instruction(target_index)
    if target is not None and target.opname in {"POP_TOP", "END_FOR"}:
        return False
    if _is_synthetic_nop_exit(ctx, target_index):
        return False
    return not _for_iter_jump_keeps_iterator()


def _is_synthetic_nop_exit(ctx: OpcodeDispatcher, target_index: int) -> bool:
    """Return true for compact test streams that use terminal ``NOP`` cleanup."""
    target = ctx.get_instruction(target_index)
    return (
        target is not None
        and target.opname == "NOP"
        and ctx.get_instruction(target_index + 1) is None
    )


def _for_iter_jump_keeps_iterator() -> bool:
    """Return the host CPython ``FOR_ITER`` exhausted-branch stack convention."""
    try:
        return dis.stack_effect(dis.opmap["FOR_ITER"], 0, jump=True) >= 0
    except (KeyError, ValueError):
        return True


def push_for_iter_exit_sentinel(
    state: VMState,
    *,
    name: str | None = None,
    push_sentinel: bool = True,
    pop_iterator: bool = False,
) -> VMState:
    """Shape the exhausted ``FOR_ITER`` stack for the target bytecode dialect.

    CPython 3.12+ keeps the iterator for ``END_FOR`` cleanup and therefore needs a
    synthetic sentinel in pysymex's normalized stack model. CPython 3.11 pops the
    iterator on the exhausted branch unless bytecode has an explicit cleanup
    ``POP_TOP`` or a synthetic test stream requests a sentinel.
    """
    if pop_iterator and state.stack:
        state.pop()
    if not push_sentinel:
        return state
    if name is None:
        return state.push(SymbolicNoneType())
    return state.push(SymbolicNoneType(name))
