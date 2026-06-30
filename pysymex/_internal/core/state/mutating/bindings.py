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

"""Local, global, heap, and write-event mutation helpers for VM state."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.state.mixin.types import VMStateMixinAttributes
from pysymex._internal.core.state.types import UNBOUND, UnboundType

if TYPE_CHECKING:
    from pysymex._internal.core.effects.events import WriteEvent
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class VMStateBindingMixin(VMStateMixinAttributes):
    """Mutate name bindings, heap slots, and effect ledgers in one path."""

    def record_freed_var(self, name: str) -> VMState:
        """Mark a variable as freed/deleted. Returns ``self``."""
        if name not in self.freed_vars:
            self.freed_vars.add(name)
            self._cached_hash = None
        return cast("VMState", self)

    def store_heap(self, address: int, value: StackValue) -> VMState:
        """Store a value in symbolic memory at *address*. Returns ``self``.

        Invalidates the cached state hash to ensure correct path deduplication.
        """
        self.memory[address] = value
        self._cached_hash = None
        return cast("VMState", self)

    def load_heap(self, address: int, default: StackValue | None = None) -> StackValue | None:
        """Load a value from symbolic memory at *address*."""
        return self.memory.get(address, default)

    def set_local(self, name: str, value: StackValue | UnboundType) -> VMState:
        """Mutate a local binding and return this state.

        Side Effects:
            ``UNBOUND`` removes any stored local value, records the name as
            freed, and invalidates the cached structural hash.
        """
        if value is UNBOUND:
            if name in self.local_vars:
                del self.local_vars[name]
                self._cached_hash = None
            self.record_freed_var(name)
            return cast("VMState", self)
        self.local_vars[name] = cast("StackValue", value)
        self._cached_hash = None
        return cast("VMState", self)

    def set_global(self, name: str, value: StackValue) -> VMState:
        """Set global variable *name* to *value*. Returns ``self``."""
        self.global_vars[name] = value
        self._cached_hash = None
        return cast("VMState", self)

    def record_write_event(self, event: WriteEvent) -> VMState:
        """Append a modeled write event for effect-sensitive analyses."""
        self.write_events.append(event)
        self._cached_hash = None
        return cast("VMState", self)

    def get_local(self, name: str) -> StackValue | UnboundType:
        """Get a local variable, or UNBOUND if not found or cleared."""
        if name in self.local_vars:
            return self.local_vars[name]
        return UNBOUND

    def get_global(self, name: str) -> StackValue | None:
        """Get a global variable, or None if not found."""
        return self.global_vars.get(name)
