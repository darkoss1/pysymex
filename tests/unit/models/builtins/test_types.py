"""Tests for builtin types models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.state import create_initial_state
from pysymex.models.builtins.types import (
    BuiltinTypeModel,
    TypeModel,
    TypeModelResult,
    _new_side_effects,  # type: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


class DummyTypeModel(TypeModel):
    """A concrete implementation of TypeModel for testing matches."""

    def __init__(self, name: str, py_type: type | None = None) -> None:
        self.name = name
        self.python_type = py_type

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> TypeModelResult:
        """Dummy apply."""
        return TypeModelResult(value=None)


class TestTypesModel:
    """Test class for builtin types models."""

    def test_new_side_effects_returns_empty_dict(self) -> None:
        """Verify that _new_side_effects produces a fresh, empty dictionary."""
        res = _new_side_effects()  # type: ignore[reportPrivateUsage]  # Testing private utility
        assert isinstance(res, dict)
        assert len(res) == 0

    def test_type_model_matches_python_type(self) -> None:
        """Verify TypeModel.matches uses identity check on python_type."""
        model = DummyTypeModel(name="int", py_type=int)
        assert model.matches(int) is True
        assert model.matches(str) is False

    def test_type_model_matches_name(self) -> None:
        """Verify TypeModel.matches falls back to __name__ attribute check."""
        model = DummyTypeModel(name="DummyClass")

        class DummyClass:
            pass

        class OtherClass:
            pass

        assert model.matches(DummyClass) is True
        assert model.matches(OtherClass) is False

    def test_type_model_matches_str(self) -> None:
        """Verify TypeModel.matches falls back to string representation check."""
        model = DummyTypeModel(name="StrClass")

        class StrClass:
            def __str__(self) -> str:
                return "StrClass"

        class OtherStrClass:
            def __str__(self) -> str:
                return "OtherStrClass"

        assert model.matches(StrClass()) is True
        assert model.matches(OtherStrClass()) is False

    def test_builtin_type_model_apply(self) -> None:
        """Verify BuiltinTypeModel.apply returns the underlying python type."""
        model = BuiltinTypeModel(int)
        state = create_initial_state()
        result = model.apply([], {}, state)

        assert isinstance(result, TypeModelResult)
        assert result.value is int
        assert len(result.constraints) == 0
        assert result.side_effects == {}
