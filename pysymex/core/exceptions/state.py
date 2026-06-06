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

"""Exception propagation path and state models."""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from pysymex.core.constants import Z3_TRUE
from pysymex.core.exceptions.objects import ExceptionHandler, SymbolicException, TryBlock


@dataclass
class ExceptionPath:
    """Track one modeled exception path and its handling metadata."""

    exception: SymbolicException
    path_condition: z3.BoolRef = field(default_factory=lambda: Z3_TRUE)
    handlers_tried: list[ExceptionHandler] = field(default_factory=list[ExceptionHandler])
    caught_by: ExceptionHandler | None = None
    propagated: bool = False


@dataclass
class ExceptionState:
    """Maintain try-stack and modeled exception-path bookkeeping."""

    try_stack: list[TryBlock] = field(default_factory=list[TryBlock])
    current_exception: SymbolicException | None = None
    exception_paths: list[ExceptionPath] = field(default_factory=list[ExceptionPath])
    suppressed: list[SymbolicException] = field(default_factory=list[SymbolicException])

    def push_try(self, block: TryBlock) -> None:
        """Push a modeled protected block onto the handler stack."""
        self.try_stack.append(block)

    def pop_try(self) -> TryBlock | None:
        """Pop the innermost modeled block, or return ``None`` if empty."""
        if self.try_stack:
            return self.try_stack.pop()
        return None

    def current_try(self) -> TryBlock | None:
        """Return the innermost modeled block, or ``None`` if empty."""
        if self.try_stack:
            return self.try_stack[-1]
        return None

    def raise_exception(
        self,
        exc: SymbolicException,
        path_condition: z3.BoolRef | None = None,
    ) -> ExceptionPath:
        """Set ``exc`` as current and append its recorded path.

        Notes:
            The provided path condition is recorded only; this method does not
            add constraints to a solver.
        """
        self.current_exception = exc
        path = ExceptionPath(
            exception=exc,
            path_condition=path_condition or Z3_TRUE,
        )
        self.exception_paths.append(path)
        return path

    def handle_exception(
        self,
        exc: SymbolicException,
    ) -> tuple[ExceptionHandler | None, int | None]:
        """Return the nearest modeled handler and target PC for ``exc``."""
        for block in reversed(self.try_stack):
            for handler in block.handlers:
                if handler.catches(exc):
                    return handler, handler.target_pc
        return None, None

    def clear_exception(self) -> None:
        """Clear the currently active modeled exception."""
        self.current_exception = None

    def suppress(self, exc: SymbolicException) -> None:
        """Record ``exc`` as suppressed and clear it when currently active."""
        self.suppressed.append(exc)
        if self.current_exception == exc:
            self.clear_exception()

    def clone(self) -> ExceptionState:
        """Return a shallow copy of this exception bookkeeping state.

        Limitations:
            Existing ``TryBlock`` and ``ExceptionPath`` objects are shared with
            the source state.
        """
        return ExceptionState(
            try_stack=list(self.try_stack),
            current_exception=self.current_exception,
            exception_paths=list(self.exception_paths),
            suppressed=list(self.suppressed),
        )
