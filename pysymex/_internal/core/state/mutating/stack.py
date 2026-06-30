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

"""Operand-stack mutation helpers for path-local VM state."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.state.mixin.types import VMStateMixinAttributes
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

logger = get_logger(__name__)


class VMStateStackMixin(VMStateMixinAttributes):
    """Mutate the operand stack while preserving structural-hash invalidation."""

    def push(self, value: StackValue) -> VMState:
        """Push *value* onto the operand stack. Returns ``self``."""
        self.stack.append(value)
        self._cached_hash = None
        return cast("VMState", self)

    def pop(self) -> StackValue:
        """Pop a value from the operand stack.

        Raises:
            VMStateError: If the operand stack is empty.

        """
        if not self.stack:
            logger.warning("VM stack underflow on pop at pc=%s", self.pc)
            msg = "Stack underflow"
            raise VMStateError(msg)
        self._cached_hash = None
        return self.stack.pop()

    def peek(self, n: int = 0) -> StackValue:
        """Return the ``n``-th value from the top without mutating the stack.

        Raises:
            VMStateError: If ``n`` is outside the current operand stack.

        """
        if len(self.stack) <= n:
            logger.warning("VM stack underflow on peek position=%d pc=%s", n, self.pc)
            msg = f"Stack underflow: cannot peek at position {n}"
            raise VMStateError(msg)
        return self.stack[-(n + 1)]
