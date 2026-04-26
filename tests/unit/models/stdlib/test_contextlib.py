from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


def _load_contextlib_models() -> ModuleType:
    module_path = (
        Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "contextlib.py"
    )
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_contextlib", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib contextlib models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contextlib_models = _load_contextlib_models()


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
        def _gen() -> object:
            yield 5

        cm = contextlib_models.ContextManagerModel()(_gen)
        with cm as value:
            assert value == 5

    def test_error_path(self) -> None:
        def _bad_gen() -> object:
            if False:
                yield None

        cm = contextlib_models.ContextManagerModel()(_bad_gen)
        with pytest.raises(RuntimeError, match="didn't yield"):
            with cm:
                pass


class TestAsyncContextManagerModel:
    """Test suite for pysymex.models.stdlib.contextlib.AsyncContextManagerModel."""

    def test_faithfulness(self) -> None:
        async def _runner() -> int:
            async def _agen() -> object:
                yield 7

            cm = contextlib_models.AsyncContextManagerModel()(_agen)
            async with cm as value:
                return int(value)

        assert asyncio.run(_runner()) == 7

    def test_error_path(self) -> None:
        async def _runner() -> None:
            async def _bad_agen() -> object:
                if False:
                    yield None

            cm = contextlib_models.AsyncContextManagerModel()(_bad_agen)
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
