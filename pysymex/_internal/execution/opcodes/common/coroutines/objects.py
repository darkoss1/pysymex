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

"""Modeled coroutine identity and retained resume request objects."""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.memory.cow.dicts import CowDict
    from pysymex._internal.typing.protocols import StackValue

COROUTINE_RESUME_PROTOCOL = "__coroutine_resume__"
_COROUTINE_ID_COUNTER = itertools.count()


def _next_coroutine_identity() -> int:
    """Return a process-local coroutine identity stable across dataclass copies."""
    return next(_COROUTINE_ID_COUNTER)


@dataclass(frozen=True, slots=True)
class ModeledCoroutine:
    """Path-local coroutine object created by calling an ``async def`` function."""

    name: str
    function: object
    args: tuple[StackValue, ...]
    kwargs: tuple[tuple[str, StackValue], ...]
    started: bool = False
    closed: bool = False
    suspended_locals: CowDict[str, StackValue] | None = None
    suspended_stack: tuple[StackValue, ...] = ()
    instructions: tuple[dis.Instruction, ...] = ()
    exception_entries: tuple[object, ...] = ()
    resume_pc: int | None = None
    identity: int = field(default_factory=_next_coroutine_identity)

    def send(self, _value: object) -> object:
        """Send must be dispatched by symbolic execution, not called natively."""
        msg = "ModeledCoroutine.send must be dispatched by the symbolic VM"
        raise RuntimeError(msg)

    def throw(self, *_args: object) -> object:
        """Throw must be dispatched by symbolic execution, not called natively."""
        msg = "ModeledCoroutine.throw must be dispatched by the symbolic VM"
        raise RuntimeError(msg)

    def close(self) -> object:
        """Close must be dispatched by symbolic execution, not called natively."""
        msg = "ModeledCoroutine.close must be dispatched by the symbolic VM"
        raise RuntimeError(msg)

    def __await__(self) -> object:
        """Await must be dispatched by symbolic execution, not called natively."""
        msg = "ModeledCoroutine.__await__ must be dispatched by the symbolic VM"
        raise RuntimeError(msg)


@dataclass(frozen=True, slots=True)
class CoroutineResumeRequest:
    coroutine: ModeledCoroutine
