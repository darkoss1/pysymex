"""Models for the contextlib module.

This module provides models for Python's contextlib standard library,
including contextmanager decorators and context utilities.
"""

from __future__ import annotations


import logging

from collections.abc import Callable, Generator

from dataclasses import dataclass

from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ContextManagerModel:
    """Model for contextmanager decorator."""

    def __call__(self, func: Callable[..., Any]) -> Any:
        """Transform a generator function into a context manager."""

        return _ContextManager(func)


class _ContextManager:
    """Wrapper that transforms a generator into a context manager."""

    def __init__(self, func: Callable[..., Any]) -> None:
        self._func: Callable[..., Any] = func

        self._generator: Generator[Any, Any, Any] | None = None

    def __enter__(self) -> Any:
        """Enter the context."""

        gen = self._func()

        self._generator = gen

        try:
            return next(gen)

        except StopIteration as exc:
            raise RuntimeError("Generator didn't yield") from exc

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_val: Any, exc_tb: Any
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

    def __call__(self, func: Callable[..., Any]) -> Any:
        """Transform an async generator function into an async context manager."""

        return _AsyncContextManager(func)


class _AsyncContextManager:
    """Wrapper that transforms an async generator into an async context manager."""

    def __init__(self, func: Callable[..., Any]) -> None:
        self._func: Callable[..., Any] = func

        self._generator: Any = None

    async def __aenter__(self) -> Any:
        """Enter the async context."""

        self._generator = self._func()

        try:
            return await self._generator.__anext__()

        except StopAsyncIteration as exc:
            raise RuntimeError("Async generator didn't yield") from exc

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_val: Any, exc_tb: Any
    ) -> bool | None:
        """Exit the async context."""

        if self._generator is None:
            return None

        gen: Any = self._generator

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

    def __enter__(self) -> ContextDecoratorModel:
        """Enter the context."""

        return self

    def __exit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> bool | None:
        """Exit the context."""

        return None

    def __call__(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorate a function to run within the context."""

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with self:
                return func(*args, **kwargs)

        return wrapper


class ExitStackModel:
    """Model for ExitStack - a context manager that maintains a stack of exit callbacks."""

    def __init__(self) -> None:
        self._exit_callbacks: list[tuple[Callable[..., Any], tuple[Any, ...], dict[str, Any]]] = []

    def __enter__(self) -> ExitStackModel:
        return self

    def __exit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> bool:
        suppressed: bool = False

        for callback, args, kwargs in reversed(self._exit_callbacks):
            try:
                result: Any = callback(*args, **kwargs)

                if result:
                    suppressed = True

            except Exception:
                logger.debug("ExitStack callback failed", exc_info=True)

        return suppressed

    def push(self, exit: Any) -> Any:
        """Add a context manager or exit callback to the stack."""

        if hasattr(exit, "__exit__"):
            self._exit_callbacks.append((exit.__exit__, (), {}))

            return exit.__enter__()

        else:
            self._exit_callbacks.append((exit, (), {}))

            return exit

    def callback(
        self, callback: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Callable[..., Any]:
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
        self._exit_callbacks: list[tuple[Callable[..., Any], tuple[Any, ...], dict[str, Any]]] = []

    async def __aenter__(self) -> AsyncExitStackModel:
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> bool:
        suppressed: bool = False

        for callback, args, kwargs in reversed(self._exit_callbacks):
            try:
                if callable(callback):
                    result: Any = await callback(*args, **kwargs)

                    if result:
                        suppressed = True

            except Exception:
                logger.debug("AsyncExitStack callback failed", exc_info=True)

        return suppressed

    async def enter_async_context(self, cm: Any) -> Any:
        """Enter an async context manager and add its __aexit__ to the stack."""

        result = await cm.__aenter__()

        self._exit_callbacks.append((cm.__aexit__, (), {}))

        return result

    def push_async_exit(self, exit: Callable[..., Any]) -> None:
        """Add an async exit callback to the stack."""

        self._exit_callbacks.append((exit, (), {}))

    def push_async_callback(
        self, callback: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Callable[..., Any]:
        """Register an async callback to be called on exit."""

        async def wrapper() -> Any:
            return await callback(*args, **kwargs)

        self._exit_callbacks.append((wrapper, (), {}))

        return callback


CONTEXTLIB_MODELS: dict[str, Any] = {
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
    "redirect_stdout": lambda _new_target: type(
        "redirect_stdout",
        (),
        {
            "__enter__": lambda self: None,
            "__exit__": lambda self, *args: None,
        },
    )(),
    "redirect_stderr": lambda _new_target: type(
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
