"""Tests for builtin models registry initialization."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.state import create_initial_state
from pysymex.models.builtins.__init__ import ModelRegistry
from pysymex.models.builtins.base import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


class DummyFunctionModel(FunctionModel):
    """Dummy model for testing registry features."""

    def __init__(self, name: str, qualname: str) -> None:
        self.name = name
        self.qualname = qualname

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return ModelResult(value=42)


class TestModelRegistry:
    """Test class for the builtin model registry."""

    def test_model_registry_initialization_registers_defaults(self) -> None:
        """Verify that default models are pre-loaded upon registry creation."""
        registry = ModelRegistry()

        models = registry.list_models()
        assert len(models) > 0
        assert "int" in models
        assert "float" in models
        assert registry.get("int") is not None

    def test_model_registry_register_stores_model(self) -> None:
        """Verify register() stores the model under both name and qualname."""
        registry = ModelRegistry()
        model = DummyFunctionModel(name="dummy", qualname="builtins.dummy")

        registry.register(model)

        assert registry.get("dummy") is model
        assert registry.get("builtins.dummy") is model

    def test_model_registry_get_retrieves_model(self) -> None:
        """Verify get() retrieves exactly what was registered."""
        registry = ModelRegistry()
        model = DummyFunctionModel(name="test_get", qualname="test_get")

        registry.register(model)

        assert registry.get("test_get") is model
        assert registry.get("missing_key") is None

    def test_model_registry_apply_with_func_name(self) -> None:
        """Verify apply() uses the function's __name__ attribute for routing."""
        registry = ModelRegistry()
        model = DummyFunctionModel(name="my_func", qualname="my_func")
        registry.register(model)
        state = create_initial_state()

        class FuncWithDunderName:
            __name__ = "my_func"

        result = registry.apply(FuncWithDunderName(), [], {}, state)

        assert result is not None
        assert result.value == 42

    def test_model_registry_apply_with_str_fallback(self) -> None:
        """Verify apply() falls back to str() when __name__ is absent."""
        registry = ModelRegistry()
        model = DummyFunctionModel(name="string_representation", qualname="string_representation")
        registry.register(model)
        state = create_initial_state()

        class FuncWithStr:
            def __str__(self) -> str:
                return "string_representation"

        result = registry.apply(FuncWithStr(), [], {}, state)

        assert result is not None
        assert result.value == 42

    def test_model_registry_apply_returns_none_for_missing(self) -> None:
        """Verify apply() returns None when no mapped model exists."""
        registry = ModelRegistry()
        state = create_initial_state()

        class UnmappedFunc:
            __name__ = "never_registered_func"

        result = registry.apply(UnmappedFunc(), [], {}, state)

        assert result is None

    def test_model_registry_has_model_true(self) -> None:
        """Verify has_model() returns True for registered functions by name or str."""
        registry = ModelRegistry()
        model = DummyFunctionModel(name="has_model_func", qualname="has_model_func")
        registry.register(model)

        class RegisteredFunc:
            __name__ = "has_model_func"

        class RegisteredStrFunc:
            def __str__(self) -> str:
                return "has_model_func"

        assert registry.has_model(RegisteredFunc()) is True
        assert registry.has_model(RegisteredStrFunc()) is True

    def test_model_registry_has_model_false(self) -> None:
        """Verify has_model() returns False for unknown functions."""
        registry = ModelRegistry()

        class UnknownFunc:
            __name__ = "unknown_function_abc"

        assert registry.has_model(UnknownFunc()) is False

    def test_model_registry_list_models(self) -> None:
        """Verify list_models() returns deduplicated model names."""
        registry = ModelRegistry()
        model1 = DummyFunctionModel(name="list1", qualname="list1_qual")
        model2 = DummyFunctionModel(name="list2", qualname="list2_qual")

        registry.register(model1)
        registry.register(model2)

        models = registry.list_models()
        assert "list1" in models
        assert "list2" in models
        assert "list1_qual" not in models
