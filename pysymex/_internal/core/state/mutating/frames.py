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

"""Block-stack and call-stack mutation helpers for VM state."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.state.mixin.types import VMStateMixinAttributes

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import BlockInfo, CallFrame


class VMStateFrameMixin(VMStateMixinAttributes):
    """Mutate control-flow block and call-frame stacks in one path."""

    def enter_block(self, block: BlockInfo) -> VMState:
        """Push *block* onto the block stack. Returns ``self``."""
        self.block_stack.append(block)
        self._cached_hash = None
        return cast("VMState", self)

    def exit_block(self) -> BlockInfo | None:
        """Pop the innermost block from the block stack.

        Returns the popped ``BlockInfo``, or ``None`` if the stack is empty.
        """
        if self.block_stack:
            block = self.block_stack.pop()
            self._cached_hash = None
            return block
        return None

    def push_call(self, frame: CallFrame) -> VMState:
        """Push *frame* onto the call stack. Returns ``self``."""
        self.call_stack.append(frame)
        self._cached_hash = None
        return cast("VMState", self)

    def pop_call(self) -> CallFrame | None:
        """Pop the top call frame.

        Returns the popped ``CallFrame``, or ``None`` if the stack is empty.
        """
        if self.call_stack:
            frame = self.call_stack.pop()
            self._cached_hash = None
            return frame
        return None

    def current_block(self) -> BlockInfo | None:
        """Get the current control flow block."""
        return self.block_stack[-1] if self.block_stack else None

    def call_depth(self) -> int:
        """Get the current call stack depth."""
        return len(self.call_stack)
