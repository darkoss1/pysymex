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

"""Stack and fused-name helpers for local, global, and closure opcode handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.state.types import VMStateError

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState


class LocalStackOps:
    """Domain owner for local opcode stack depth and fused fast-local name decoding."""

    @staticmethod
    def require_depth(
        state: VMState,
        instr: dis.Instruction,
        required_depth: int,
        purpose: str,
    ) -> None:
        """Raise :class:`~pysymex._internal.core.state.types.VMStateError` when the stack is too shallow."""
        if len(state.stack) < required_depth:
            msg = (
                f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
                f"cannot satisfy {required_depth} item(s) for {purpose}"
            )
            raise VMStateError(
                msg,
            )

    @staticmethod
    def fast_names(instr: dis.Instruction) -> tuple[str, ...]:
        """Decode local variable names for fused fast-local opcodes (3.13+)."""
        argrepr = getattr(instr, "argrepr", "")
        if isinstance(argrepr, str) and argrepr:
            cleaned = argrepr.strip().strip("()")
            if "," in cleaned:
                parts = tuple(p.strip() for p in cleaned.split(",") if p.strip())
                if parts:
                    return parts
            if cleaned:
                return (cleaned,)

        argval = instr.argval
        if isinstance(argval, str):
            cleaned = argval.strip().strip("()")
            if "," in cleaned:
                parts = tuple(p.strip() for p in cleaned.split(",") if p.strip())
                if parts:
                    return parts
            if cleaned:
                return (cleaned,)
        elif isinstance(argval, tuple):
            return tuple(str(x) for x in cast("tuple[object, ...]", argval))

        return (str(argval),)
