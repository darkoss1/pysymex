"""Tests for exception builtin models."""

from __future__ import annotations

import z3

from pysymex.core.exceptions.analyzer import BUILTIN_EXCEPTIONS
from pysymex.core.state import create_initial_state
from pysymex.core.types.scalars import SymbolicValue
from pysymex.models.builtins.exceptions import ExceptionTypeModel, create_exception_models
from pysymex.models.builtins.types import TypeModelResult


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
        """Verify ExceptionTypeModel.apply returns the type object when no args are passed."""
        model = ExceptionTypeModel(ValueError)
        state = create_initial_state()

        result = model.apply([], {}, state)

        assert isinstance(result, TypeModelResult)
        assert result.value is ValueError
        assert len(result.constraints) == 0
        assert result.side_effects == {}

    def test_create_exception_models_returns_all_builtins(self) -> None:
        """Verify create_exception_models generates a model for every tracked builtin exception."""
        models = create_exception_models()

        assert len(models) == len(BUILTIN_EXCEPTIONS)
        for model in models:
            assert isinstance(model, ExceptionTypeModel)
            assert model.python_type in BUILTIN_EXCEPTIONS
