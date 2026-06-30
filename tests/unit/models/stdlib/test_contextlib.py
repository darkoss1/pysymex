from __future__ import annotations

import types
from collections.abc import Generator
from contextlib import AbstractContextManager
from typing import cast

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.stdlib.contextlib.managers import (
    ContextManagerFactory,
    ContextManagerModel,
)
from pysymex._internal.models.stdlib.contextlib.protocols import ContextManagerProtocol
from pysymex._internal.models.stdlib.contextlib.stacks import (
    ExitStackConstructorModel,
    ExitStackModel,
)
from pysymex._internal.models.stdlib.contextlib.stubs import Suppress
from pysymex._internal.models.stdlib.registry import get_stdlib_model


class _CM:
    def __enter__(self) -> object:
        return 1

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> bool:
        _ = exc_val, exc_tb
        return False


class TestContextManagerProtocol:
    """Test suite for pysymex._internal.models.stdlib.contextlib.ContextManagerProtocol."""

    def test_faithfulness(self) -> None:
        assert isinstance(_CM(), ContextManagerProtocol)

    def test_error_path(self) -> None:
        assert not isinstance(object(), ContextManagerProtocol)


class TestContextManagerModel:
    """Test suite for pysymex._internal.models.stdlib.contextlib.ContextManagerModel."""

    def test_faithfulness(self) -> None:
        def _gen() -> Generator[object, object, object]:
            yield 5

        factory = ContextManagerModel()(_gen)
        cm = cast(AbstractContextManager[object], factory())
        with cm as value:
            assert value == 5

    def test_error_path(self) -> None:
        def _bad_gen() -> Generator[object, object, object]:
            yield from ()

        factory = ContextManagerModel()(_bad_gen)
        cm = cast(AbstractContextManager[object], factory())
        with pytest.raises(RuntimeError, match="didn't yield"):
            with cm:
                pass

    def test_apply_returns_context_manager_factory(self) -> None:
        def _gen() -> Generator[object, object, object]:
            yield 9

        result = ContextManagerModel().apply([_gen], {}, VMState(pc=0))

        assert isinstance(result.value, ContextManagerFactory)
        cm = cast(AbstractContextManager[object], result.value())
        with cm as value:
            assert value == 9


class TestExitStackModel:
    """Test suite for pysymex._internal.models.stdlib.contextlib.ExitStackModel."""

    def test_faithfulness(self) -> None:
        stack = ExitStackModel()
        called: list[str] = []

        def _cb() -> None:
            called.append("x")

        stack.callback(_cb)
        stack.__exit__(None, None, None)
        assert called == ["x"]

    def test_error_path(self) -> None:
        stack = ExitStackModel()
        moved = stack.pop_all()
        assert isinstance(moved, ExitStackModel)

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
                _ = exc_val, exc_tb
                called.append("exit")
                return False

        stack = ExitStackModel()

        assert stack.enter_context(_TrackedCM()) == 2
        assert stack.__exit__(None, None, None) is False
        assert called == ["exit"]


class TestExitStackConstructorModel:
    """Test suite for pysymex._internal.models.stdlib.contextlib.ExitStackConstructorModel."""

    def test_constructor_returns_concrete_backed_stack_model(self) -> None:
        result = ExitStackConstructorModel().apply([], {}, VMState(pc=0))

        assert isinstance(result.value, SymbolicValue)
        assert isinstance(result.value.value, ExitStackModel)
        assert result.constraints == ()


def test_exit_stack_constructor_registered_in_stdlib_registry() -> None:
    """The executable ExitStack constructor model is available to call dispatch."""
    assert isinstance(
        get_stdlib_model("contextlib.ExitStack"),
        ExitStackConstructorModel,
    )
    assert isinstance(get_stdlib_model("contextlib.ExitStack"), ExitStackConstructorModel)


def test_contextmanager_registered_in_stdlib_registry() -> None:
    """The executable contextmanager decorator model is available to call dispatch."""
    assert isinstance(
        get_stdlib_model("contextlib.contextmanager"),
        ContextManagerModel,
    )
    assert isinstance(get_stdlib_model("contextlib.contextmanager"), ContextManagerModel)


def test_suppress_model_matches_only_configured_exception_types() -> None:
    """The bounded suppress stub preserves stdlib suppression type semantics."""
    manager = Suppress(ValueError)

    assert manager.suppresses("ValueError") is True
    assert manager.suppresses("ZeroDivisionError") is False
