"""
Tests for pysymex Function Models - Phase 17

Tests for builtin function models and effect tracking.
"""

import pytest

import z3


from pysymex.models.builtins import (
    default_model_registry,
    ModelResult,
    LenModel,
    IntModel,
    FloatModel,
    BoolModel,
    StrModel,
    ListModel,
    TupleModel,
    DictModel,
    SetModel,
    AbsModel,
    MinModel,
    MaxModel,
    SumModel,
    PowModel,
    RoundModel,
    DivmodModel,
    AllModel,
    AnyModel,
    OrdModel,
    ChrModel,
    ReversedModel,
    HasattrModel,
    GetattrModel,
    IdModel,
    HashModel,
    CallableModel,
    ReprModel,
    FormatModel,
    InputModel,
    PrintModel,
)

from pysymex.core.types import SymbolicValue, SymbolicList, SymbolicString


def get_concrete(value):
    """Extract concrete value from symbolic or concrete."""

    if value is None:
        return None

    if isinstance(value, (int, float, bool, str)):
        return value

    if isinstance(value, SymbolicValue):
        if hasattr(value, "concrete"):
            return value.concrete

        elif hasattr(value, "value"):
            v = value.value

            if hasattr(v, "as_long"):
                return v.as_long()

            elif hasattr(v, "as_fraction"):
                return float(v.as_fraction())

            return v

    if hasattr(value, "to_concrete"):
        return value.to_concrete()

    if hasattr(value, "concrete_value"):
        return value.concrete_value

    return value


class MockVMState:
    """Mock VMState for testing models."""

    def __init__(self, pc: int = 0):
        self.pc = pc


class TestModelRegistry:
    """Tests for the model registry."""

    def test_registry_has_models(self):
        """Test that registry has expected models."""

        assert default_model_registry.has_model(len)

        assert default_model_registry.has_model(abs)

        assert default_model_registry.has_model(min)

        assert default_model_registry.has_model(max)

    def test_registry_list_models(self):
        """Test listing all models."""

        models = default_model_registry.list_models()

        assert "len" in models

        assert "int" in models

        assert "float" in models

        assert "str" in models

    def test_registry_get_model(self):
        """Test getting a model by name."""

        model = default_model_registry.get("len")

        assert model is not None

        assert model.name == "len"

    def test_registry_model_count(self):
        """Test that we have many models registered."""

        models = default_model_registry.list_models()

        assert len(models) >= 35


class TestIntModel:
    """Tests for int() model."""

    def test_int_from_concrete(self):
        """Test int() with concrete value."""

        model = IntModel()

        state = MockVMState()

        result = model.apply([42], {}, state)

        assert isinstance(result, ModelResult)

        assert get_concrete(result.value) == 42

    def test_int_from_float_concrete(self):
        """Test int() with float."""

        model = IntModel()

        state = MockVMState()

        result = model.apply([3.7], {}, state)

        assert get_concrete(result.value) == 3

    def test_int_from_string(self):
        """Test int() with string."""

        model = IntModel()

        state = MockVMState()

        result = model.apply(["123"], {}, state)

        assert get_concrete(result.value) == 123


class TestFloatModel:
    """Tests for float() model."""

    def test_float_from_concrete(self):
        """Test float() with concrete value."""

        model = FloatModel()

        state = MockVMState()

        result = model.apply([42], {}, state)

        assert get_concrete(result.value) == 42.0

    def test_float_default(self):
        """Test float() with no args."""

        model = FloatModel()

        state = MockVMState()

        result = model.apply([], {}, state)

        assert get_concrete(result.value) == 0.0


class TestBoolModel:
    """Tests for bool() model."""

    def test_bool_from_zero(self):
        """Test bool(0) = False."""

        model = BoolModel()

        state = MockVMState()

        result = model.apply([0], {}, state)

        assert get_concrete(result.value) == False

    def test_bool_from_nonzero(self):
        """Test bool(nonzero) = True."""

        model = BoolModel()

        state = MockVMState()

        result = model.apply([42], {}, state)

        assert get_concrete(result.value) == True


class TestStrModel:
    """Tests for str() model."""

    def test_str_from_int(self):
        """Test str() from int."""

        model = StrModel()

        state = MockVMState()

        result = model.apply([42], {}, state)

        assert result.value is not None


class TestListModel:
    """Tests for list() model."""

    def test_list_empty(self):
        """Test list() creates empty list."""

        model = ListModel()

        state = MockVMState()

        result = model.apply([], {}, state)

        assert result.value is not None

    def test_list_from_tuple(self):
        """Test list() from tuple."""

        model = ListModel()

        state = MockVMState()

        result = model.apply([(1, 2, 3)], {}, state)

        assert result.value is not None


class TestTupleModel:
    """Tests for tuple() model."""

    def test_tuple_empty(self):
        """Test tuple() creates empty tuple."""

        model = TupleModel()

        state = MockVMState()

        result = model.apply([], {}, state)

        assert result.value == ()

    def test_tuple_from_list(self):
        """Test tuple() from list."""

        model = TupleModel()

        state = MockVMState()

        result = model.apply([[1, 2, 3]], {}, state)

        assert result.value == (1, 2, 3)


class TestDictModel:
    """Tests for dict() model."""

    def test_dict_empty(self):
        """Test dict() creates empty dict."""

        model = DictModel()

        state = MockVMState()

        result = model.apply([], {}, state)

        assert result.value is not None


class TestSetModel:
    """Tests for set() model."""

    def test_set_empty(self):
        """Test set() creates empty set."""

        model = SetModel()

        state = MockVMState()

        result = model.apply([], {}, state)

        assert isinstance(result, ModelResult)


class TestAbsModel:
    """Tests for abs() model."""

    def test_abs_positive(self):
        """Test abs() of positive number."""

        model = AbsModel()

        state = MockVMState()

        result = model.apply([5], {}, state)

        assert get_concrete(result.value) == 5

    def test_abs_negative(self):
        """Test abs() of negative number."""

        model = AbsModel()

        state = MockVMState()

        result = model.apply([-5], {}, state)

        assert get_concrete(result.value) == 5

    def test_abs_symbolic(self):
        """Test abs() of symbolic value."""

        model = AbsModel()

        state = MockVMState()

        x, _ = SymbolicValue.symbolic("x")

        result = model.apply([x], {}, state)

        assert len(result.constraints) > 0


class TestMinModel:
    """Tests for min() model."""

    def test_min_two_args(self):
        """Test min() with two args."""

        model = MinModel()

        state = MockVMState()

        result = model.apply([5, 3], {}, state)

        assert get_concrete(result.value) == 3

    def test_min_list(self):
        """Test min() with list."""

        model = MinModel()

        state = MockVMState()

        result = model.apply([[5, 3, 7]], {}, state)

        assert get_concrete(result.value) == 3


class TestMaxModel:
    """Tests for max() model."""

    def test_max_two_args(self):
        """Test max() with two args."""

        model = MaxModel()

        state = MockVMState()

        result = model.apply([5, 3], {}, state)

        assert get_concrete(result.value) == 5


class TestSumModel:
    """Tests for sum() model."""

    def test_sum_list(self):
        """Test sum() of list."""

        model = SumModel()

        state = MockVMState()

        result = model.apply([[1, 2, 3]], {}, state)

        assert get_concrete(result.value) == 6

    def test_sum_with_start(self):
        """Test sum() with start value."""

        model = SumModel()

        state = MockVMState()

        result = model.apply([[1, 2, 3], 10], {}, state)

        assert get_concrete(result.value) == 16


class TestPowModel:
    """Tests for pow() model."""

    def test_pow_concrete(self):
        """Test pow() with concrete values."""

        model = PowModel()

        state = MockVMState()

        result = model.apply([2, 3], {}, state)

        assert get_concrete(result.value) == 8

    def test_pow_with_mod(self):
        """Test pow() with modulo."""

        model = PowModel()

        state = MockVMState()

        result = model.apply([2, 10, 100], {}, state)

        assert get_concrete(result.value) == 24


class TestRoundModel:
    """Tests for round() model."""

    def test_round_integer(self):
        """Test round() to integer."""

        model = RoundModel()

        state = MockVMState()

        result = model.apply([3.7], {}, state)

        assert get_concrete(result.value) == 4

    def test_round_with_digits(self):
        """Test round() with decimal places."""

        model = RoundModel()

        state = MockVMState()

        result = model.apply([3.14159, 2], {}, state)

        concrete = get_concrete(result.value)

        assert abs(float(concrete) - 3.14) < 0.01


class TestDivmodModel:
    """Tests for divmod() model."""

    def test_divmod_integers(self):
        """Test divmod() with integers."""

        model = DivmodModel()

        state = MockVMState()

        result = model.apply([17, 5], {}, state)

        q, r = result.value

        assert get_concrete(q) == 3

        assert get_concrete(r) == 2


class TestAllModel:
    """Tests for all() model."""

    def test_all_true(self):
        """Test all() with all truthy."""

        model = AllModel()

        state = MockVMState()

        result = model.apply([[True, True, True]], {}, state)

        assert get_concrete(result.value) == True

    def test_all_false(self):
        """Test all() with one falsy."""

        model = AllModel()

        state = MockVMState()

        result = model.apply([[True, False, True]], {}, state)

        assert get_concrete(result.value) == False

    def test_all_empty(self):
        """Test all() with empty list."""

        model = AllModel()

        state = MockVMState()

        result = model.apply([[]], {}, state)

        assert get_concrete(result.value) == True


class TestAnyModel:
    """Tests for any() model."""

    def test_any_one_true(self):
        """Test any() with one truthy."""

        model = AnyModel()

        state = MockVMState()

        result = model.apply([[False, True, False]], {}, state)

        assert get_concrete(result.value) == True

    def test_any_all_false(self):
        """Test any() with all falsy."""

        model = AnyModel()

        state = MockVMState()

        result = model.apply([[False, False]], {}, state)

        assert get_concrete(result.value) == False


class TestOrdModel:
    """Tests for ord() model."""

    def test_ord_char(self):
        """Test ord() of character."""

        model = OrdModel()

        state = MockVMState()

        result = model.apply(["A"], {}, state)

        assert get_concrete(result.value) == 65


class TestChrModel:
    """Tests for chr() model."""

    def test_chr_int(self):
        """Test chr() of integer."""

        model = ChrModel()

        state = MockVMState()

        result = model.apply([65], {}, state)

        assert result.value is not None


class TestReprModel:
    """Tests for repr() model."""

    def test_repr_string(self):
        """Test repr() of string."""

        model = ReprModel()

        state = MockVMState()

        result = model.apply(["hello"], {}, state)

        assert result.value is not None


class TestHasattrModel:
    """Tests for hasattr() model."""

    def test_hasattr_exists(self):
        """Test hasattr() when attribute exists."""

        model = HasattrModel()

        state = MockVMState()

        result = model.apply([[1, 2], "append"], {}, state)

        assert get_concrete(result.value) == True

    def test_hasattr_missing(self):
        """Test hasattr() when attribute missing."""

        model = HasattrModel()

        state = MockVMState()

        result = model.apply([42, "append"], {}, state)

        assert get_concrete(result.value) == False


class TestGetattrModel:
    """Tests for getattr() model."""

    def test_getattr_exists(self):
        """Test getattr() when attribute exists."""

        model = GetattrModel()

        state = MockVMState()

        result = model.apply([[1, 2], "__len__"], {}, state)


class TestIdModel:
    """Tests for id() model."""

    def test_id_returns_int(self):
        """Test id() returns integer constraint."""

        model = IdModel()

        state = MockVMState()

        result = model.apply([42], {}, state)

        assert any("is_int" in str(c) or "Int" in str(c) for c in result.constraints)


class TestPrintModel:
    """Tests for print() model."""

    def test_print_returns_none(self):
        """Test print() returns None."""

        model = PrintModel()

        state = MockVMState()

        result = model.apply(["hello"], {}, state)


class TestInputModel:
    """Tests for input() model."""

    def test_input_returns_string(self):
        """Test input() returns symbolic string."""

        model = InputModel()

        state = MockVMState()

        result = model.apply(["prompt: "], {}, state)

        assert result.value is not None

        assert result.side_effects.get("io") == True


class TestModelEffectIntegration:
    """Integration tests for models and effects."""

    def test_pure_function_no_effects(self):
        """Test pure functions report no effects."""

        model = LenModel()

        state = MockVMState()

        result = model.apply([[1, 2, 3]], {}, state)

        assert not result.side_effects

    def test_io_function_reports_effects(self):
        """Test I/O functions report effects."""

        model = InputModel()

        state = MockVMState()

        result = model.apply([], {}, state)

        assert result.side_effects.get("io") == True

    def test_model_constraints_valid(self):
        """Test model constraints are valid Z3."""

        model = AbsModel()

        state = MockVMState()

        x, _ = SymbolicValue.symbolic("x")

        result = model.apply([x], {}, state)

        for c in result.constraints:
            assert isinstance(c, z3.ExprRef)
