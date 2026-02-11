"""Models for the contextlib module.

This module provides models for Python's contextlib standard library,
including contextmanager decorators and context utilities.
"""

from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class ContextManagerModel:
    """Model for contextmanager decorator."""

    def __call__(self, func: Callable) -> Callable:
        """Transform a generator function into a context manager."""
        return _ContextManager(func)


class _ContextManager:
    """Wrapper that transforms a generator into a context manager."""

    def __init__(self, func: Callable) -> None:
        self._func = func
        self._generator = None

    def __enter__(self) -> Any:
        """Enter the context."""
        self._generator = self._func()
        try:
            return next(self._generator)
        except StopIteration:
            raise RuntimeError("Generator didn't yield")

    def __exit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> bool | None:
        """Exit the context."""
        if self._generator is None:
            return None

        try:
            if exc_type is None:
                try:
                    next(self._generator)
                except StopIteration:
                    return None
                else:
                    raise RuntimeError("Generator didn't stop")
            else:
                try:
                    self._generator.throw(exc_type, exc_val, exc_tb)
                except StopIteration:
                    return True
                except exc_type:
                    return False
        finally:
            self._generator.close()


@dataclass
class AsyncContextManagerModel:
    """Model for asynccontextmanager decorator."""

    def __call__(self, func: Callable) -> Callable:
        """Transform an async generator function into an async context manager."""
        return _AsyncContextManager(func)


class _AsyncContextManager:
    """Wrapper that transforms an async generator into an async context manager."""

    def __init__(self, func: Callable) -> None:
        self._func = func
        self._generator = None

    async def __aenter__(self) -> Any:
        """Enter the async context."""
        self._generator = self._func()
        try:
            return await self._generator.__anext__()
        except StopAsyncIteration:
            raise RuntimeError("Async generator didn't yield")

    async def __aexit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> bool | None:
        """Exit the async context."""
        if self._generator is None:
            return None

        try:
            if exc_type is None:
                try:
                    await self._generator.__anext__()
                except StopAsyncIteration:
                    return None
                else:
                    raise RuntimeError("Async generator didn't stop")
            else:
                try:
                    await self._generator.athrow(exc_type, exc_val, exc_tb)
                except StopAsyncIteration:
                    return True
                except exc_type:
                    return False
        finally:
            await self._generator.aclose()


@dataclass
class ContextDecoratorModel:
    """Model for ContextDecorator base class."""

    def __enter__(self) -> "ContextDecoratorModel":
        """Enter the context."""
        return self

    def __exit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> bool | None:
        """Exit the context."""
        return None

    def __call__(self, func: Callable) -> Callable:
        """Decorate a function to run within the context."""

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with self:
                return func(*args, **kwargs)

        return wrapper


class ExitStackModel:
    """Model for ExitStack - a context manager that maintains a stack of exit callbacks."""

    def __init__(self) -> None:
        self._exit_callbacks: list[tuple[Callable, tuple, dict]] = []

    def __enter__(self) -> "ExitStackModel":
        return self

    def __exit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> bool:
        suppressed = False
        for callback, args, kwargs in reversed(self._exit_callbacks):
            try:
                result = callback(*args, **kwargs)
                if result:
                    suppressed = True
            except Exception:
                pass
        return suppressed

    def push(self, exit: Callable | Any) -> Any:
        """Add a context manager or exit callback to the stack."""
        if hasattr(exit, "__exit__"):
            self._exit_callbacks.append((exit.__exit__, (), {}))
            return exit.__enter__()
        else:
            self._exit_callbacks.append((exit, (), {}))
            return exit

    def callback(self, callback: Callable, *args: Any, **kwargs: Any) -> Callable:
        """Register a callback to be called on exit."""
        self._exit_callbacks.append((callback, args, kwargs))
        return callback

    def pop_all(self) -> "ExitStackModel":
        """Transfer all callbacks to a new ExitStack."""
        new_stack = ExitStackModel()
        new_stack._exit_callbacks = self._exit_callbacks[:]
        self._exit_callbacks.clear()
        return new_stack


class AsyncExitStackModel:
    """Model for AsyncExitStack - async version of ExitStack."""

    def __init__(self) -> None:
        self._exit_callbacks: list[tuple[Callable, tuple, dict]] = []

    async def __aenter__(self) -> "AsyncExitStackModel":
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> bool:
        suppressed = False
        for callback, args, kwargs in reversed(self._exit_callbacks):
            try:
                if callable(callback):
                    result = await callback(*args, **kwargs)
                    if result:
                        suppressed = True
            except Exception:
                pass
        return suppressed

    async def enter_async_context(self, cm: Any) -> Any:
        """Enter an async context manager and add its __aexit__ to the stack."""
        result = await cm.__aenter__()
        self._exit_callbacks.append((cm.__aexit__, (), {}))
        return result

    def push_async_exit(self, exit: Callable) -> None:
        """Add an async exit callback to the stack."""
        self._exit_callbacks.append((exit, (), {}))

    def push_async_callback(self, callback: Callable, *args: Any, **kwargs: Any) -> Callable:
        """Register an async callback to be called on exit."""

        async def wrapper():
            return await callback(*args, **kwargs)

        self._exit_callbacks.append((wrapper, (), {}))
        return callback


CONTEXTLIB_MODELS = {
    "contextmanager": ContextManagerModel(),
    "asynccontextmanager": AsyncContextManagerModel(),
    "ContextDecorator": ContextDecoratorModel,
    "ExitStack": ExitStackModel,
    "AsyncExitStack": AsyncExitStackModel,
    "closing": lambda obj: obj,
    "aclosing": lambda obj: obj,
    "suppress": type(
        "suppress",
        (),
        {
            "__enter__": lambda self: self,
            "__exit__": lambda self, *args: True,
        },
    ),
    "redirect_stdout": lambda new_target: type(
        "redirect_stdout",
        (),
        {
            "__enter__": lambda self: None,
            "__exit__": lambda self, *args: None,
        },
    )(),
    "redirect_stderr": lambda new_target: type(
        "redirect_stderr",
        (),
        {
            "__enter__": lambda self: None,
            "__exit__": lambda self, *args: None,
        },
    )(),
}


def get_contextlib_model(name: str) -> Any | None:
    """Get a contextlib model by name."""
    return CONTEXTLIB_MODELS.get(name)


__all__ = [
    "ContextManagerModel",
    "AsyncContextManagerModel",
    "ContextDecoratorModel",
    "ExitStackModel",
    "AsyncExitStackModel",
    "CONTEXTLIB_MODELS",
    "get_contextlib_model",
]
