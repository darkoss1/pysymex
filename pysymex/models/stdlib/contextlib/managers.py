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

import types
from collections.abc import AsyncGenerator, Callable, Generator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self, cast

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.builtins.core.helpers import type_error_side_effect

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue


def _contextmanager_type_error(message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"contextmanager_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=(constraint,),
        side_effects=type_error_side_effect("contextlib.contextmanager", message),
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
            raise RuntimeError("contextmanager function is not natively callable")
        gen = cast("Generator[object, object, object]", func(*self._args, **self._kwargs))
        self._generator = gen
        try:
            return next(gen)
        except StopIteration as exc:
            raise RuntimeError("Generator didn't yield") from exc

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
                    raise RuntimeError("Generator didn't stop")
            else:
                try:
                    gen.throw(exc_type, exc_val, exc_tb)
                except StopIteration:
                    return True
                except exc_type:
                    return False
        finally:
            gen.close()


@dataclass
class AsyncContextManagerModel:
    """Model for asynccontextmanager decorator."""

    def __call__(self, func: Callable[..., AsyncGenerator[object, object]]) -> object:
        """Transform an async generator function into an async context manager."""
        return AsyncContextManager(func)


class AsyncContextManager:
    """Wrapper that transforms an async generator into an async context manager."""

    def __init__(self, func: Callable[..., AsyncGenerator[object, object]]) -> None:
        """Initialize a new _AsyncContextManager instance."""
        self._func: Callable[..., AsyncGenerator[object, object]] = func
        self._generator: AsyncGenerator[object, object] | None = None

    async def __aenter__(self) -> object:
        """Enter the async context."""
        self._generator = self._func()
        try:
            return await self._generator.__anext__()
        except StopAsyncIteration as exc:
            raise RuntimeError("Async generator didn't yield") from exc

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool | None:
        """Exit the async context."""
        if self._generator is None:
            return None

        gen: AsyncGenerator[object, object] = self._generator
        try:
            if exc_type is None:
                try:
                    await gen.__anext__()
                except StopAsyncIteration:
                    return None
                else:
                    raise RuntimeError("Async generator didn't stop")
            else:
                try:
                    await gen.athrow(exc_type, exc_val, exc_tb)
                except StopAsyncIteration:
                    return True
                except exc_type:
                    return False
        finally:
            await gen.aclose()


@dataclass
class ContextDecoratorModel:
    """Model for ContextDecorator base class."""

    def __enter__(self) -> Self:
        """Enter the context."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool | None:
        """Exit the context."""
        return None

    def __call__(self, func: Callable[..., object]) -> Callable[..., object]:
        """Decorate a function to run within the context."""

        def wrapper(*args: object, **kwargs: object) -> object:
            with self:
                return func(*args, **kwargs)

        return wrapper


__all__ = [
    "AsyncContextManagerModel",
    "ContextDecoratorModel",
    "ContextManagerModel",
    "AsyncContextManager",
    "ContextManager",
]
