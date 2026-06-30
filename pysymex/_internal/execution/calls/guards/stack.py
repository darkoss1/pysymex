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

"""CALL stack-depth and null-marker guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.base import SymbolicNoneType

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState


def require_call_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    """Enforce minimum stack depth for opcode execution."""
    if len(state.stack) < required_depth:
        msg = (
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )
        raise VMStateError(
            msg,
        )


def is_call_null_marker(value: object) -> bool:
    """Return whether a stack slot is the CALL-method null placeholder."""
    return value is None or isinstance(value, SymbolicNoneType)
