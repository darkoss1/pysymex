"""Tests for exception builtin models."""

from __future__ import annotations

import builtins

import pytest
import z3

from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.exceptions.builtins import BUILTIN_EXCEPTIONS
from pysymex.core.state.factory import create_initial_state
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.exceptions import ExceptionTypeModel, create_exception_models
from pysymex.models.builtins import get_default_model_registry
from pysymex.models.builtins.results import is_raised_exception_effect
from pysymex.models.builtins.types import TypeModelResult
from pysymex.typing import StackValue


INVALID_EXCEPTION_GROUP_CASES: list[tuple[type[BaseException], list[StackValue], str]] = [
    (BaseExceptionGroup, [1, [SymbolicValue.from_const(1)]], "TypeError"),
    (ExceptionGroup, ["message", []], "ValueError"),
    (ExceptionGroup, ["message", [1]], "ValueError"),
]


class TestExceptionsModel:
    """Test class for exception models."""

    def test_exception_type_model_apply_with_args(self) -> None:
        """Verify ExceptionTypeModel.apply tracks symbolic instances when args are given."""
        model = ExceptionTypeModel(ValueError)
        state = create_initial_state()

        result = model.apply(["an error occurred"], {}, state)

        assert isinstance(result, TypeModelResult)
        assert isinstance(result.value, SymbolicValue)
        assert result.value.name.startswith("ValueError_instance_")
        assert len(result.constraints) == 1
        assert isinstance(result.constraints[0], z3.ExprRef)
        assert result.side_effects == {}

    def test_exception_type_model_apply_without_args(self) -> None:
        """ValueError() produces an exception instance, not the ValueError class object."""
        model = ExceptionTypeModel(ValueError)
        state = create_initial_state()

        result = model.apply([], {}, state)

        assert isinstance(result, TypeModelResult)
        assert isinstance(result.value, SymbolicValue)
        assert result.value.name.startswith("ValueError_instance_")
        assert len(result.constraints) == 1
        assert result.side_effects == {}
        payload = getattr(result.value, "_modeled_object", None)
        assert z3.is_false(result.value.is_none)
        assert isinstance(payload, SymbolicException)
        assert payload.exc_type is ValueError

    @pytest.mark.parametrize(
        "exc_type",
        [
            UnicodeDecodeError,
            UnicodeEncodeError,
            UnicodeTranslateError,
            BaseExceptionGroup,
            ExceptionGroup,
        ],
    )
    def test_required_argument_exception_constructor_emits_type_error(
        self, exc_type: type[BaseException]
    ) -> None:
        """Exception constructors with required parameters reject empty calls."""
        result = ExceptionTypeModel(exc_type).apply([], {}, create_initial_state())

        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"

    @pytest.mark.parametrize(
        ("exc_type", "args"),
        [
            (UnicodeDecodeError, ["utf-8", "not-bytes", 0, 1, "reason"]),
            (UnicodeEncodeError, ["utf-8", b"not-text", 0, 1, "reason"]),
            (UnicodeTranslateError, [b"not-text", 0, 1, "reason"]),
            (UnicodeDecodeError, ["utf-8", b"value", "zero", 1, "reason"]),
            (UnicodeEncodeError, ["utf-8", "value", 0, 1, b"reason"]),
        ],
    )
    def test_unicode_exception_constructor_rejects_wrong_concrete_payload_types(
        self, exc_type: type[BaseException], args: list[StackValue]
    ) -> None:
        """Unicode error constructors reject definitely invalid concrete payloads."""
        result = ExceptionTypeModel(exc_type).apply(args, {}, create_initial_state())

        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"

    @pytest.mark.parametrize(
        ("exc_type", "args"),
        [
            (UnicodeDecodeError, ["utf-8", b"value", 0, 1, "reason"]),
            (UnicodeEncodeError, ["utf-8", "value", 0, 1, "reason"]),
            (UnicodeTranslateError, ["value", 0, 1, "reason"]),
        ],
    )
    def test_unicode_exception_constructor_accepts_valid_concrete_payload_types(
        self, exc_type: type[BaseException], args: list[StackValue]
    ) -> None:
        """Valid concrete Unicode error payload types remain modeled as instances."""
        result = ExceptionTypeModel(exc_type).apply(args, {}, create_initial_state())

        assert "raised_exception" not in result.side_effects

    @pytest.mark.parametrize(("exc_type", "args", "exception_type"), INVALID_EXCEPTION_GROUP_CASES)
    def test_exception_group_constructor_rejects_definite_invalid_concrete_inputs(
        self, exc_type: type[BaseException], args: list[StackValue], exception_type: str
    ) -> None:
        """Exception-group constructors reject definite invalid concrete inputs."""
        result = ExceptionTypeModel(exc_type).apply(args, {}, create_initial_state())

        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == exception_type

    def test_create_exception_models_returns_all_builtins(self) -> None:
        """Verify create_exception_models generates a model for every tracked builtin exception."""
        models = create_exception_models()

        assert len(models) == len(BUILTIN_EXCEPTIONS)
        for model in models:
            assert isinstance(model, ExceptionTypeModel)
            assert model.python_type in BUILTIN_EXCEPTIONS

    def test_default_registry_applies_builtin_exception_constructor(self) -> None:
        """Builtin exception classes are resolved through the default model registry."""
        result = get_default_model_registry().apply(
            RuntimeError, ["boom"], {}, create_initial_state()
        )

        assert result is not None
        assert isinstance(result.value, SymbolicValue)
        assert result.value.name.startswith("RuntimeError_instance_")

    def test_default_registry_includes_exception_groups_and_available_new_exceptions(self) -> None:
        """Builtin exception registration tracks modern CPython exception classes."""
        registry = get_default_model_registry()

        assert registry.get("BaseExceptionGroup") is not None
        assert registry.get("ExceptionGroup") is not None
        assert registry.get("EncodingWarning") is not None
        optional = getattr(builtins, "PythonFinalizationError", None)
        if optional is not None:
            assert registry.get("PythonFinalizationError") is not None
