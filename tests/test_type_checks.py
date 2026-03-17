"""Tests for pysymex.core.type_checks — type predicate utilities.

Covers: is_overloaded_arithmetic, is_type_subscription, BUILTIN_TYPE_NAMES.
"""

from __future__ import annotations

import pytest

from pysymex.core.type_checks import (
    BUILTIN_TYPE_NAMES,
    is_overloaded_arithmetic,
    is_type_subscription,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight stand-in objects with the attributes the predicates inspect
# ---------------------------------------------------------------------------

class _FakeOperand:
    """Simulates a SymbolicValue-like object with configurable name/_name/model_name."""

    def __init__(self, *, _name: str = "", model_name: str | None = None, _type: str | None = None):
        self._name = _name
        self.model_name = model_name
        self._type = _type


class _FakeContainer:
    """Simulates a container with _name / name / model_name attributes."""

    def __init__(self, *, _name: str = "", name: str = "", model_name: str | None = None):
        self._name = _name
        self.name = name
        self.model_name = model_name


# ---------------------------------------------------------------------------
# BUILTIN_TYPE_NAMES
# ---------------------------------------------------------------------------

class TestBuiltinTypeNames:

    def test_contains_common_types(self):
        for name in ("list", "dict", "tuple", "set", "int", "float", "str", "bool"):
            assert name in BUILTIN_TYPE_NAMES

    def test_contains_typing_types(self):
        for name in ("Optional", "Union", "Callable", "Any"):
            assert name in BUILTIN_TYPE_NAMES

    def test_is_frozenset(self):
        assert isinstance(BUILTIN_TYPE_NAMES, frozenset)

    def test_not_contains_random_name(self):
        assert "foobar_xyz" not in BUILTIN_TYPE_NAMES


# ---------------------------------------------------------------------------
# is_overloaded_arithmetic
# ---------------------------------------------------------------------------

class TestIsOverloadedArithmetic:

    def test_z3_name_detected(self):
        left = _FakeOperand(_name="z3_int_val")
        right = _FakeOperand(_name="plain")
        assert is_overloaded_arithmetic(left, right) is True

    def test_numpy_name_detected(self):
        left = _FakeOperand(_name="numpy_array_x")
        right = _FakeOperand(_name="y")
        assert is_overloaded_arithmetic(left, right) is True

    def test_torch_name_detected(self):
        left = _FakeOperand(_name="x")
        right = _FakeOperand(_name="torch_tensor")
        assert is_overloaded_arithmetic(left, right) is True

    def test_model_name_z3(self):
        left = _FakeOperand(model_name="z3")
        right = _FakeOperand()
        assert is_overloaded_arithmetic(left, right) is True

    def test_model_name_numpy(self):
        left = _FakeOperand()
        right = _FakeOperand(model_name="numpy")
        assert is_overloaded_arithmetic(left, right) is True

    def test_type_arithref(self):
        left = _FakeOperand(_type="ArithRef")
        right = _FakeOperand()
        assert is_overloaded_arithmetic(left, right) is True

    def test_type_ndarray(self):
        left = _FakeOperand()
        right = _FakeOperand(_type="ndarray")
        assert is_overloaded_arithmetic(left, right) is True

    def test_plain_operands(self):
        left = _FakeOperand(_name="x_var")
        right = _FakeOperand(_name="y_var")
        assert is_overloaded_arithmetic(left, right) is False

    def test_empty_names(self):
        left = _FakeOperand()
        right = _FakeOperand()
        assert is_overloaded_arithmetic(left, right) is False

    def test_decimal_model_name(self):
        left = _FakeOperand(model_name="decimal")
        right = _FakeOperand()
        assert is_overloaded_arithmetic(left, right) is True

    def test_symbolic_in_name(self):
        left = _FakeOperand(_name="symbolic_add_result")
        right = _FakeOperand(_name="a")
        assert is_overloaded_arithmetic(left, right) is True


# ---------------------------------------------------------------------------
# is_type_subscription
# ---------------------------------------------------------------------------

class TestIsTypeSubscription:

    def test_global_list(self):
        container = _FakeContainer(_name="global_list")
        assert is_type_subscription(container) is True

    def test_global_dict(self):
        container = _FakeContainer(_name="global_dict")
        assert is_type_subscription(container) is True

    def test_import_Optional(self):
        container = _FakeContainer(_name="import_Optional")
        assert is_type_subscription(container) is True

    def test_model_name_builtin(self):
        container = _FakeContainer(model_name="tuple")
        assert is_type_subscription(container) is True

    def test_not_type_subscription(self):
        container = _FakeContainer(_name="my_list_var")
        assert is_type_subscription(container) is False

    def test_global_nonbuiltin(self):
        container = _FakeContainer(_name="global_MyClass")
        assert is_type_subscription(container) is False

    def test_import_nonbuiltin(self):
        container = _FakeContainer(_name="import_MyModule")
        assert is_type_subscription(container) is False

    def test_model_name_none(self):
        container = _FakeContainer()
        assert is_type_subscription(container) is False
