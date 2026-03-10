"""Models for the contextlib module.

This module provides models for Python's contextlib standard library,
including contextmanager decorators and context utilities.
"""

from __future__ import annotations

import logging
import types
from collections.abc import Callable, Generator
from dataclasses import dataclass
from typing import Any, Self

logger = logging.getLogger(__name__)


@dataclass
class ContextManagerModel:
    """Model for contextmanager decorator."""

    def __call__(self, func: Callable[..., object]) -> object:
        """Transform a generator function into a context manager."""
        return _ContextManager(func)


class _ContextManager:
    """Wrapper that transforms a generator into a context manager."""

    def __init__(self, func: Callable[..., object]) -> None:
        self._func: Callable[..., object] = func
        self._generator: Generator[Any, Any, Any] | None = None

    def __enter__(self) -> object:
        """Enter the context."""
        gen = self._func()
        self._generator = gen
        try:
            return next(gen)
        except StopIteration as exc:
            raise RuntimeError("Generator didn't yield") from exc

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_val: object, exc_tb: object
    ) -> bool | None:
        """Exit the context."""
        if self._generator is None:
            return None

        gen: Generator[Any, Any, Any] = self._generator
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

    def __call__(self, func: Callable[..., object]) -> object:
        """Transform an async generator function into an async context manager."""
        return _AsyncContextManager(func)


class _AsyncContextManager:
    """Wrapper that transforms an async generator into an async context manager."""

    def __init__(self, func: Callable[..., object]) -> None:
        self._func: Callable[..., object] = func
        self._generator: object = None

    async def __aenter__(self) -> object:
        """Enter the async context."""
        self._generator = self._func()
        try:
            return await self._generator.__anext__()
        except StopAsyncIteration as exc:
            raise RuntimeError("Async generator didn't yield") from exc

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_val: object, exc_tb: object
    ) -> bool | None:
        """Exit the async context."""
        if self._generator is None:
            return None

        gen: object = self._generator
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


class ExitStackModel:
    """Model for ExitStack - a context manager that maintains a stack of exit callbacks."""

    def __init__(self) -> None:
        self._exit_callbacks: list[
            tuple[Callable[..., object], tuple[object, ...], dict[str, object]]
        ] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool:
        suppressed: bool = False
        for callback, args, kwargs in reversed(self._exit_callbacks):
            try:
                result: object = callback(*args, **kwargs)
                if result:
                    suppressed = True
            except Exception:
                logger.debug("ExitStack callback failed", exc_info=True)
        return suppressed

    def push(self, exit: object) -> object:
        """Add a context manager or exit callback to the stack."""
        if hasattr(exit, "__exit__"):
            self._exit_callbacks.append((exit.__exit__, (), {}))
            return exit.__enter__()
        else:
            self._exit_callbacks.append((exit, (), {}))
            return exit

    def callback(
        self, callback: Callable[..., object], *args: object, **kwargs: object
    ) -> Callable[..., object]:
        """Register a callback to be called on exit."""
        self._exit_callbacks.append((callback, args, kwargs))
        return callback

    def pop_all(self) -> ExitStackModel:
        """Transfer all callbacks to a new ExitStack."""
        new_stack = ExitStackModel()
        new_stack._exit_callbacks = self._exit_callbacks[:]
        self._exit_callbacks.clear()
        return new_stack


class AsyncExitStackModel:
    """Model for AsyncExitStack - async version of ExitStack."""

    def __init__(self) -> None:
        self._exit_callbacks: list[
            tuple[Callable[..., object], tuple[object, ...], dict[str, object]]
        ] = []

    async def __aenter__(self) -> AsyncExitStackModel:
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: object, exc_tb: object) -> bool:
        suppressed: bool = False
        for callback, args, kwargs in reversed(self._exit_callbacks):
            try:
                if callable(callback):
                    result: object = await callback(*args, **kwargs)
                    if result:
                        suppressed = True
            except Exception:
                logger.debug("AsyncExitStack callback failed", exc_info=True)
        return suppressed

    async def enter_async_context(self, cm: object) -> object:
        """Enter an async context manager and add its __aexit__ to the stack."""
        result = await cm.__aenter__()
        self._exit_callbacks.append((cm.__aexit__, (), {}))
        return result

    def push_async_exit(self, exit: Callable[..., object]) -> None:
        """Add an async exit callback to the stack."""
        self._exit_callbacks.append((exit, (), {}))

    def push_async_callback(
        self, callback: Callable[..., object], *args: object, **kwargs: object
    ) -> Callable[..., object]:
        """Register an async callback to be called on exit."""

        async def wrapper() -> object:
            return await callback(*args, **kwargs)

        self._exit_callbacks.append((wrapper, (), {}))
        return callback


def _stub_closing(obj: object) -> object:
    return obj


def _stub_aclosing(obj: object) -> object:
    return obj


def _stub_redirect_stdout(_new_target: object) -> object:
    return type(
        "redirect_stdout",
        (),
        {"__enter__": lambda self: None, "__exit__": lambda self, *args: None},
    )()


def _stub_redirect_stderr(_new_target: object) -> object:
    return type(
        "redirect_stderr",
        (),
        {"__enter__": lambda self: None, "__exit__": lambda self, *args: None},
    )()


_SUPPRESS_TYPE: type = type(
    "suppress",
    (),
    {"__enter__": lambda self: self, "__exit__": lambda self, *args: True},
)


CONTEXTLIB_MODELS: dict[str, object] = {
    "contextmanager": ContextManagerModel(),
    "asynccontextmanager": AsyncContextManagerModel(),
    "ContextDecorator": ContextDecoratorModel,
    "ExitStack": ExitStackModel,
    "AsyncExitStack": AsyncExitStackModel,
    "closing": _stub_closing,
    "aclosing": _stub_aclosing,
    "suppress": _SUPPRESS_TYPE,
    "redirect_stdout": _stub_redirect_stdout,
    "redirect_stderr": _stub_redirect_stderr,
}


def get_contextlib_model(name: str) -> object | None:
    """Get a contextlib model by name."""
    return CONTEXTLIB_MODELS.get(name)


__all__ = [
    "CONTEXTLIB_MODELS",
    "AsyncContextManagerModel",
    "AsyncExitStackModel",
    "ContextDecoratorModel",
    "ContextManagerModel",
    "ExitStackModel",
    "get_contextlib_model",
]
