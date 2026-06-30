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

"""Context manager decorator models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    import types
    from collections.abc import Callable, Generator

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _contextmanager_type_error(message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"contextmanager_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=(constraint,),
        side_effects=SideEffects.type_error("contextlib.contextmanager", message),
    )


@dataclass(frozen=True)
class ContextManagerFactory:
    """Callable wrapper returned by ``contextlib.contextmanager``."""

    func: object

    def __call__(self, *args: object, **kwargs: object) -> ContextManager:
        """Create one generator-backed context manager instance."""
        return ContextManager(self.func, args, kwargs)


@dataclass
class ContextManagerModel(FunctionModel):
    """Model for the ``contextlib.contextmanager`` decorator."""

    name = "contextmanager"
    qualname = "contextlib.contextmanager"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _contextmanager_type_error(
                "contextmanager() expects exactly one callable argument",
                state,
            )
        return ModelResult(value=ContextManagerFactory(args[0]))

    def __call__(
        self,
        func: Callable[..., Generator[object, object, object]],
    ) -> ContextManagerFactory:
        """Transform a generator function into a context-manager factory."""
        return ContextManagerFactory(func)


class ContextManager:
    """Wrapper that transforms a generator into a context manager."""

    def __init__(
        self,
        func: object,
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
    ) -> None:
        """Initialize a new _ContextManager instance."""
        self._func: object = func
        self._args: tuple[object, ...] = args
        self._kwargs: dict[str, object] = dict(kwargs or {})
        self._generator: object | None = None

    @property
    def function(self) -> object:
        """Return the wrapped generator function or symbolic function payload."""
        return self._func

    @property
    def args(self) -> tuple[object, ...]:
        """Return positional arguments captured by the context-manager factory."""
        return self._args

    @property
    def kwargs(self) -> dict[str, object]:
        """Return keyword arguments captured by the context-manager factory."""
        return dict(self._kwargs)

    @property
    def generator(self) -> object | None:
        """Return the active modeled or concrete generator, if one has been entered."""
        return self._generator

    def bind_modeled_generator(self, generator: object) -> None:
        """Attach the VM-owned generator continuation for later ``__exit__`` handling."""
        self._generator = generator

    def replace_modeled_generator(self, old: object, new: object) -> None:
        """Update the retained modeled generator when VM resume produces a new state."""
        if self._generator is old:
            self._generator = new
            return
        current_id = getattr(self._generator, "identity", None)
        old_id = getattr(old, "identity", None)
        if current_id is not None and current_id == old_id:
            self._generator = new

    def __enter__(self) -> object:
        """Enter the context."""
        func = self._func
        if not callable(func):
            msg = "contextmanager function is not natively callable"
            raise RuntimeError(msg)
        gen = cast("Generator[object, object, object]", func(*self._args, **self._kwargs))
        self._generator = gen
        try:
            return next(gen)
        except StopIteration as exc:
            msg = "Generator didn't yield"
            raise RuntimeError(msg) from exc

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool | None:
        """Exit the context."""
        if self._generator is None:
            return None

        gen = cast("Generator[object, object, object]", self._generator)
        try:
            if exc_type is None:
                try:
                    next(gen)
                except StopIteration:
                    return None
                else:
                    msg = "Generator didn't stop"
                    raise RuntimeError(msg)
            else:
                try:
                    gen.throw(exc_type, exc_val, exc_tb)
                except StopIteration:
                    return True
                except exc_type:
                    return False
        finally:
            gen.close()
