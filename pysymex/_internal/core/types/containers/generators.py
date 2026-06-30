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

"""Path-local generator continuation descriptors shared across layers."""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.memory.cow.dicts import CowDict
    from pysymex._internal.typing.protocols import StackValue

_GENERATOR_ID_COUNTER = itertools.count()


def _next_generator_identity() -> int:
    """Return a process-local generator identity stable across dataclass copies."""
    return next(_GENERATOR_ID_COUNTER)


@dataclass(frozen=True, slots=True)
class ModeledGenerator:
    """Path-local generator continuation represented by suspended VM state."""

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
    identity: int = field(default_factory=_next_generator_identity)

    def send(self, value: object) -> object:
        """Resume the generator with *value* (must be dispatched by the VM, not natively)."""
        msg = "ModeledGenerator.send must be dispatched by the symbolic VM"
        raise RuntimeError(msg)

    def throw(self, *args: object) -> object:
        """Throw into the generator (must be dispatched by the VM, not natively)."""
        msg = "ModeledGenerator.throw must be dispatched by the symbolic VM"
        raise RuntimeError(msg)

    def close(self) -> object:
        """Close the generator (must be dispatched by the VM, not natively)."""
        msg = "ModeledGenerator.close must be dispatched by the symbolic VM"
        raise RuntimeError(msg)

    def hash_value(self) -> int:
        """Return a stable hash for deduplicating generator continuations in caches."""
        retained = repr(
            (self.function, self.args, self.kwargs, self.suspended_locals, self.suspended_stack),
        )
        return hash((self.name, self.started, self.closed, self.resume_pc, retained))
