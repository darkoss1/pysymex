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

"""ExitStack models for contextlib."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self

import z3

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.logging.root import get_logger
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.contextlib.protocols import (
    ContextManagerProtocol,
    ExitCallback,
)

if TYPE_CHECKING:
    import types
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

logger = get_logger(__name__)


def _empty_callback_kwargs() -> dict[str, object]:
    return {}


@dataclass(slots=True)
class _ExitStackCallback:
    callback: object
    args: tuple[object, ...] = ()
    kwargs: dict[str, object] = field(default_factory=_empty_callback_kwargs)
    receives_exception: bool = False


class ExitStackModel:
    """Model for ExitStack - a context manager that maintains a stack of exit callbacks."""

    def __init__(self) -> None:
        """Initialize a new ExitStackModel instance."""
        self._exit_callbacks: list[_ExitStackCallback] = []

    def __enter__(self) -> Self:
        return self

    def get_attribute(self, name: str, bound_instance: object | None = None) -> tuple[object, bool]:
        """Return supported concrete attributes for symbolic attribute dispatch."""
        _ = bound_instance
        if name in {
            "__enter__",
            "__exit__",
            "enter_context",
            "push",
            "callback",
            "pop_all",
            "_exit_callbacks",
        }:
            return getattr(self, name), True
        return None, False

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool:
        """Exit."""
        suppressed: bool = False
        for entry in reversed(self._exit_callbacks):
            try:
                if not callable(entry.callback):
                    continue
                if entry.receives_exception:
                    result: object = entry.callback(exc_type, exc_val, exc_tb)
                else:
                    result = entry.callback(*entry.args, **entry.kwargs)
                if result:
                    suppressed = True
            except Exception:
                logger.debug("ExitStack callback failed", exc_info=True)
        return suppressed

    def enter_context(self, cm: ContextManagerProtocol) -> object:
        """Enter *cm*, register its exit callback, and return its enter value."""
        result = cm.__enter__()
        self.register_exit_callback(cm.__exit__)
        return result

    def register_exit_callback(self, callback: object) -> None:
        """Register a context-manager exit callback for trusted dispatch helpers."""
        self._exit_callbacks.append(_ExitStackCallback(callback, receives_exception=True))

    def push(self, exit: ContextManagerProtocol | ExitCallback) -> object:
        """Add a context manager or exit callback to the stack."""
        if isinstance(exit, ContextManagerProtocol):
            self.register_exit_callback(exit.__exit__)
            return exit.__enter__()
        self.register_exit_callback(exit)
        return exit

    def callback(
        self,
        callback: Callable[..., object],
        *args: object,
        **kwargs: object,
    ) -> Callable[..., object]:
        """Register a callback to be called on exit."""
        self._exit_callbacks.append(_ExitStackCallback(callback, args, kwargs))
        return callback

    def pop_all(self) -> ExitStackModel:
        """Transfer all callbacks to a new ExitStack."""
        new_stack = ExitStackModel()
        new_stack._exit_callbacks = self._exit_callbacks[:]
        self._exit_callbacks.clear()
        return new_stack


class ExitStackConstructorModel(FunctionModel):
    """Model for constructing ``contextlib.ExitStack``."""

    name = "ExitStack"
    qualname = "contextlib.ExitStack"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args or kwargs:
            result, constraint = SymbolicValue.symbolic(f"ExitStack_{state.pc}")
            return ModelResult(
                value=result,
                constraints=(constraint,),
                side_effects={
                    "potential_exception": {
                        "type": "TypeError",
                        "message": "ExitStack() takes no arguments",
                        "condition": z3.BoolVal(True),
                    },
                },
            )
        return ModelResult(value=SymbolicValue.from_const(ExitStackModel()))
