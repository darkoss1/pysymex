from __future__ import annotations

import z3
import pytest

from pysymex._typing import StackValue
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult


class _IdentityModel(FunctionModel):
    name = "identity"
    qualname = "identity"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1:
            raise TypeError("identity expects exactly one argument")
        value: StackValue = args[0]
        if isinstance(value, SymbolicValue):
            return ModelResult(value=value, constraints=(value.is_int,))
        return ModelResult(value=value)


class TestModelResult:
    """Test suite for pysymex.models.builtins.base.ModelResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        cond = z3.Int("x") > 0
        result = ModelResult(value=7, constraints=(cond,), side_effects={"printed": True})
        assert result.value == 7
        assert len(result.constraints) == 1
        assert z3.eq(result.constraints[0], cond)
        assert result.side_effects["printed"] is True


class TestFunctionModel:
    """Test suite for pysymex.models.builtins.base.FunctionModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        model = _IdentityModel()
        state = VMState()

        real_value = 42
        real_result = (lambda x: x)(real_value)
        model_result = model.apply([real_value], {}, state)

        assert model_result.value == real_result

    def test_apply_symbolic_path(self) -> None:
        """Test apply with symbolic input."""
        model = _IdentityModel()
        state = VMState()
        symbolic = SymbolicValue.from_const(3)

        result = model.apply([symbolic], {}, state)

        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) == 1

    def test_apply_error_path(self) -> None:
        """Test apply invalid input behavior."""
        model = _IdentityModel()
        state = VMState()
        with pytest.raises(TypeError):
            model.apply([], {}, state)

    def test_apply_edge_case_none(self) -> None:
        """Test apply edge-case input."""
        model = _IdentityModel()
        state = VMState()
        result = model.apply([SymbolicNone()], {}, state)
        assert isinstance(result.value, SymbolicNone)

    def test_matches(self) -> None:
        """Test matches behavior."""
        model = _IdentityModel()

        def identity() -> None:
            return None

        assert model.matches(identity) is True
        assert model.matches(str) is False
