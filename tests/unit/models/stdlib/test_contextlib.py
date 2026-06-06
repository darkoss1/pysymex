from __future__ import annotations

import asyncio
import types
from collections.abc import AsyncGenerator, Generator
from contextlib import AbstractAsyncContextManager, AbstractContextManager
from typing import cast

import pytest

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.stdlib import get_stdlib_model
from pysymex.models.stdlib import contextlib as contextlib_models


class _CM:
    def __enter__(self) -> object:
        return 1

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> bool:
        return False


class TestContextManagerProtocol:
    """Test suite for pysymex.models.stdlib.contextlib.ContextManagerProtocol."""

    def test_faithfulness(self) -> None:
        assert isinstance(_CM(), contextlib_models.ContextManagerProtocol)

    def test_error_path(self) -> None:
        assert not isinstance(object(), contextlib_models.ContextManagerProtocol)


class _ACM:
    async def __aenter__(self) -> object:
        return 1

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> bool:
        return False


class TestAsyncContextManagerProtocol:
    """Test suite for pysymex.models.stdlib.contextlib.AsyncContextManagerProtocol."""

    def test_faithfulness(self) -> None:
        assert isinstance(_ACM(), contextlib_models.AsyncContextManagerProtocol)

    def test_error_path(self) -> None:
        assert not isinstance(object(), contextlib_models.AsyncContextManagerProtocol)


class TestContextManagerModel:
    """Test suite for pysymex.models.stdlib.contextlib.ContextManagerModel."""

    def test_faithfulness(self) -> None:
        def _gen() -> Generator[object, object, object]:
            yield 5

        factory = contextlib_models.ContextManagerModel()(_gen)
        cm = cast(AbstractContextManager[object], factory())
        with cm as value:
            assert value == 5

    def test_error_path(self) -> None:
        def _bad_gen() -> Generator[object, object, object]:
            yield from ()

        factory = contextlib_models.ContextManagerModel()(_bad_gen)
        cm = cast(AbstractContextManager[object], factory())
        with pytest.raises(RuntimeError, match="didn't yield"):
            with cm:
                pass

    def test_apply_returns_context_manager_factory(self) -> None:
        def _gen() -> Generator[object, object, object]:
            yield 9

        result = contextlib_models.ContextManagerModel().apply([_gen], {}, VMState(pc=0))

        assert isinstance(result.value, contextlib_models.ContextManagerFactory)
        cm = cast(AbstractContextManager[object], result.value())
        with cm as value:
            assert value == 9


class TestAsyncContextManagerModel:
    """Test suite for pysymex.models.stdlib.contextlib.AsyncContextManagerModel."""

    def test_faithfulness(self) -> None:
        async def _runner() -> int:
            async def _agen() -> AsyncGenerator[object, object]:
                yield 7

            cm = cast(
                AbstractAsyncContextManager[object],
                contextlib_models.AsyncContextManagerModel()(_agen),
            )
            async with cm as value:
                assert isinstance(value, int)
                return value

        assert asyncio.run(_runner()) == 7

    def test_error_path(self) -> None:
        async def _runner() -> None:
            async def _bad_agen() -> AsyncGenerator[object, object]:
                for item in ():
                    yield item

            cm = cast(
                AbstractAsyncContextManager[object],
                contextlib_models.AsyncContextManagerModel()(_bad_agen),
            )
            with pytest.raises(RuntimeError, match="didn't yield"):
                async with cm:
                    pass

        asyncio.run(_runner())


class TestContextDecoratorModel:
    """Test suite for pysymex.models.stdlib.contextlib.ContextDecoratorModel."""

    def test_faithfulness(self) -> None:
        model = contextlib_models.ContextDecoratorModel()

        @model
        def _f() -> int:
            return 3

        assert _f() == 3

    def test_error_path(self) -> None:
        model = contextlib_models.ContextDecoratorModel()
        assert model.__exit__(None, None, None) is None


class TestExitStackModel:
    """Test suite for pysymex.models.stdlib.contextlib.ExitStackModel."""

    def test_faithfulness(self) -> None:
        stack = contextlib_models.ExitStackModel()
        called: list[str] = []

        def _cb() -> None:
            called.append("x")

        stack.callback(_cb)
        stack.__exit__(None, None, None)
        assert called == ["x"]

    def test_error_path(self) -> None:
        stack = contextlib_models.ExitStackModel()
        moved = stack.pop_all()
        assert isinstance(moved, contextlib_models.ExitStackModel)

    def test_enter_context_returns_enter_value_and_registers_exit(self) -> None:
        called: list[str] = []

        class _TrackedCM:
            def __enter__(self) -> object:
                return 2

            def __exit__(
                self,
                exc_type: type[BaseException] | None,
                exc_val: BaseException | None,
                exc_tb: types.TracebackType | None,
            ) -> bool:
                called.append("exit")
                return False

        stack = contextlib_models.ExitStackModel()

        assert stack.enter_context(_TrackedCM()) == 2
        assert stack.__exit__(None, None, None) is False
        assert called == ["exit"]


class TestExitStackConstructorModel:
    """Test suite for pysymex.models.stdlib.contextlib.ExitStackConstructorModel."""

    def test_constructor_returns_concrete_backed_stack_model(self) -> None:
        result = contextlib_models.ExitStackConstructorModel().apply([], {}, VMState(pc=0))

        assert isinstance(result.value, SymbolicValue)
        assert isinstance(result.value.value, contextlib_models.ExitStackModel)
        assert result.constraints == ()


class TestAsyncExitStackModel:
    """Test suite for pysymex.models.stdlib.contextlib.AsyncExitStackModel."""

    def test_faithfulness(self) -> None:
        async def _runner() -> int:
            stack = contextlib_models.AsyncExitStackModel()
            called: list[int] = []

            async def _cb() -> None:
                called.append(1)

            stack.push_async_exit(_cb)
            await stack.__aexit__(None, None, None)
            return len(called)

        assert asyncio.run(_runner()) == 1

    def test_error_path(self) -> None:
        async def _runner() -> object:
            stack = contextlib_models.AsyncExitStackModel()
            cm = _ACM()
            return await stack.enter_async_context(cm)

        assert asyncio.run(_runner()) == 1


def test_get_contextlib_model() -> None:
    """Test get_contextlib_model behavior."""
    assert contextlib_models.get_contextlib_model("ExitStack") is contextlib_models.ExitStackModel
    assert contextlib_models.get_contextlib_model("missing") is None


def test_exit_stack_constructor_registered_in_stdlib_registry() -> None:
    """The executable ExitStack constructor model is available to call dispatch."""
    assert isinstance(
        get_stdlib_model("contextlib.ExitStack"),
        contextlib_models.ExitStackConstructorModel,
    )
    assert isinstance(get_stdlib_model("ExitStack"), contextlib_models.ExitStackConstructorModel)


def test_contextmanager_registered_in_stdlib_registry() -> None:
    """The executable contextmanager decorator model is available to call dispatch."""
    assert isinstance(
        get_stdlib_model("contextlib.contextmanager"),
        contextlib_models.ContextManagerModel,
    )
    assert isinstance(get_stdlib_model("contextmanager"), contextlib_models.ContextManagerModel)


def test_suppress_model_matches_only_configured_exception_types() -> None:
    """The bounded suppress stub preserves stdlib suppression type semantics."""
    manager = contextlib_models.Suppress(ValueError)

    assert manager.suppresses("ValueError") is True
    assert manager.suppresses("ZeroDivisionError") is False
