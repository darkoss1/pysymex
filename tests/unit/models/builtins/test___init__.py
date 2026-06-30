"""Tests for builtin models registry initialization."""

from __future__ import annotations

import builtins
from typing import TYPE_CHECKING

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.models.builtins.numeric.format import HexModel
from pysymex._internal.models.builtins.registry.builtin_models import builtin_models
from pysymex._internal.models.builtins.registry.defaults import default_builtin_models
from pysymex._internal.models.builtins.registry.models import ModelRegistry
from pysymex._internal.models.builtins.types.containers.sets.constructor import SetConstructorModel
from pysymex._internal.models.builtins.types.containers.tuples.construction import (
    TupleConstructorModel,
)
from pysymex._internal.models.builtins.types.numeric.complex import ComplexConjugateModel
from pysymex._internal.models.builtins.types.numeric.float import FloatHexModel
from pysymex._internal.models.builtins.types.numeric.properties import (
    ComplexImagModel,
    ComplexRealModel,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


def create_initial_state() -> VMState:
    """Create the minimal root state needed by builtin registry tests."""
    return VMState(global_vars={"__name__": "__main__"})


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
        assert "builtins.int" in models
        assert "builtins.float" in models
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

    def test_model_registry_apply_resolves_verified_builtin(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Concrete dispatch accepts a callable owned by the builtins module."""
        registry = ModelRegistry()
        model = DummyFunctionModel(name="pysymex_dummy", qualname="builtins.pysymex_dummy")
        registry.register(model)
        state = create_initial_state()

        def pysymex_dummy() -> None:
            return None

        monkeypatch.setattr(builtins, "pysymex_dummy", pysymex_dummy, raising=False)

        result = registry.apply(pysymex_dummy, [], {}, state)

        assert result is not None
        assert result.value == 42

    def test_model_registry_apply_rejects_string_representation_fallback(self) -> None:
        """Arbitrary objects cannot acquire builtin semantics through their string form."""
        registry = ModelRegistry()
        model = DummyFunctionModel(name="string_representation", qualname="string_representation")
        registry.register(model)
        state = create_initial_state()

        class FuncWithStr:
            def __str__(self) -> str:
                return "string_representation"

        result = registry.apply(FuncWithStr(), [], {}, state)

        assert result is None

    def test_model_registry_apply_returns_none_for_missing(self) -> None:
        """Verify apply() returns None when no mapped model exists."""
        registry = ModelRegistry()
        state = create_initial_state()

        class UnmappedFunc:
            __name__ = "never_registered_func"

        result = registry.apply(UnmappedFunc(), [], {}, state)

        assert result is None

    def test_model_registry_list_models(self) -> None:
        """Verify list_models() returns deduplicated model qualnames."""
        registry = ModelRegistry()
        model1 = DummyFunctionModel(name="list1", qualname="list1_qual")
        model2 = DummyFunctionModel(name="list2", qualname="list2_qual")

        registry.register(model1)
        registry.register(model2)

        models = registry.list_models()
        assert "list1_qual" in models
        assert "list2_qual" in models
        assert "list1" not in models

    def test_model_registry_rejects_duplicate_exact_keys(self) -> None:
        registry = ModelRegistry()
        registry.register(DummyFunctionModel(name="first", qualname="custom.same"))

        with pytest.raises(ValueError, match="duplicate builtin model key"):
            registry.register(DummyFunctionModel(name="second", qualname="custom.same"))

    def test_model_registry_uses_canonical_overlapping_model_owners(self) -> None:
        """Overlapping public models resolve to the runtime-owned implementation."""
        registry = ModelRegistry()

        assert type(registry.get("tuple")) is TupleConstructorModel
        assert type(registry.get("builtins.tuple")) is TupleConstructorModel
        assert type(registry.get("set")) is SetConstructorModel
        assert type(registry.get("builtins.set")) is SetConstructorModel
        assert type(registry.get("complex.real")) is ComplexRealModel
        assert type(registry.get("complex.imag")) is ComplexImagModel
        assert type(registry.get("complex.conjugate")) is ComplexConjugateModel

    def test_builtin_name_is_not_overwritten_by_method_alias(self) -> None:
        """Global builtin lookup and qualified method lookup keep separate owners."""
        registry = ModelRegistry()

        assert type(registry.get("hex")) is HexModel
        assert type(registry.get("builtins.hex")) is HexModel
        assert type(registry.get("float.hex")) is FloatHexModel

    def test_interactive_terminal_builtins_resolve_by_seeded_object_identity(self) -> None:
        """CPython exit/quit objects resolve despite not exposing __name__."""
        registry = ModelRegistry()
        state = create_initial_state()

        exit_result = registry.apply(builtins.exit, [], {}, state)
        quit_result = registry.apply(builtins.quit, [], {}, state)
        assert exit_result is not None
        assert quit_result is not None
        exit_effect = exit_result.side_effects.get("raised_exception")
        quit_effect = quit_result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(exit_effect)
        assert SideEffects.is_raised_exception(quit_effect)
        assert exit_effect["exception_type"] == "SystemExit"
        assert quit_effect["exception_type"] == "SystemExit"

    @pytest.mark.parametrize("name", ["help", "copyright", "credits", "license"])
    def test_interactive_output_builtins_resolve_by_seeded_object_identity(self, name: str) -> None:
        """Interactive display helper objects route to their builtin output models."""
        registry = ModelRegistry()
        target = getattr(builtins, name)

        result = registry.apply(target, [], {}, create_initial_state())
        assert isinstance(result, ModelResult)
        assert result.side_effects.get("io") is True

    @pytest.mark.parametrize(
        ("name", "args"),
        [
            ("bool", [1, 2]),
            ("float", [1, 2]),
            ("int", [1, 2, 3]),
            ("str", [1, 2, 3, 4]),
            ("complex", [1, 2, 3]),
            ("list", [1, 2]),
            ("tuple", [1, 2]),
            ("dict", [1, 2]),
            ("set", [1, 2]),
            ("bytes", [1, 2, 3, 4]),
            ("bytearray", [1, 2, 3, 4]),
            ("frozenset", [(), ()]),
            ("object", [1]),
            ("globals", [1]),
            ("locals", [1]),
            ("vars", [1, 2]),
            ("dir", [1, 2]),
            ("property", [None, None, None, None, None]),
            ("super", [None, None, None]),
        ],
    )
    def test_registered_builtins_reject_definite_excess_arguments(
        self, name: str, args: list[StackValue]
    ) -> None:
        """Runtime-selected builtin owners reject excessive positional arguments."""
        result = ModelRegistry().apply(getattr(builtins, name), args, {}, create_initial_state())

        assert isinstance(result, ModelResult)
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"

    @pytest.mark.parametrize(
        "name",
        [
            "bool",
            "float",
            "list",
            "tuple",
            "set",
            "frozenset",
            "object",
            "globals",
            "locals",
            "vars",
            "dir",
        ],
    )
    def test_registered_positional_only_builtins_reject_keywords(self, name: str) -> None:
        """Positional-only constructor and namespace forms reject keyword values."""
        result = ModelRegistry().apply(
            getattr(builtins, name), [], {"unexpected": 1}, create_initial_state()
        )

        assert isinstance(result, ModelResult)
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"

    def test_default_assembly_registers_each_extended_owner_once(self) -> None:
        """Default assembly must not add parallel runtime registrations."""
        models = default_builtin_models()

        for owner in builtin_models():
            matching = [
                model
                for model in models
                if type(model) is type(owner)
                and model.name == owner.name
                and model.qualname == owner.qualname
            ]
            assert len(matching) == 1
