"""Tests for pysymex.analysis.method_models -- Method models for built-in types.

Covers:
- MethodModels.get() for str, list, dict, set methods
- Return types of method models
- Purity/readonly flags
- Parameter information
- may_raise sets
- mutates_parameters sets
"""

from __future__ import annotations

import pytest

from pysymex.analysis.method_models import MethodModels
from pysymex.analysis.function_models import FunctionSummary, ParameterInfo
from pysymex.analysis.type_inference import PyType, TypeKind


# ===================================================================
# String method models
# ===================================================================


class TestStrMethodModels:
    """Tests for str method models."""

    def test_upper_exists(self):
        model = MethodModels.get(TypeKind.STR, "upper")
        assert model is not None

    def test_upper_is_pure(self):
        model = MethodModels.get(TypeKind.STR, "upper")
        assert model.is_pure
        assert model.is_readonly

    def test_upper_returns_str(self):
        model = MethodModels.get(TypeKind.STR, "upper")
        assert model.return_type.kind == TypeKind.STR

    def test_lower_exists(self):
        model = MethodModels.get(TypeKind.STR, "lower")
        assert model is not None
        assert model.return_type.kind == TypeKind.STR

    def test_strip_has_default_param(self):
        model = MethodModels.get(TypeKind.STR, "strip")
        assert model is not None
        assert len(model.parameters) == 1
        assert model.parameters[0].has_default

    def test_split_returns_list(self):
        model = MethodModels.get(TypeKind.STR, "split")
        assert model is not None
        assert model.return_type.kind == TypeKind.LIST

    def test_join_returns_str(self):
        model = MethodModels.get(TypeKind.STR, "join")
        assert model is not None
        assert model.return_type.kind == TypeKind.STR
        assert "TypeError" in model.may_raise

    def test_find_returns_int(self):
        model = MethodModels.get(TypeKind.STR, "find")
        assert model is not None
        assert model.return_type.kind == TypeKind.INT
        assert model.is_pure

    def test_index_may_raise(self):
        model = MethodModels.get(TypeKind.STR, "index")
        assert model is not None
        assert "ValueError" in model.may_raise

    def test_startswith_returns_bool(self):
        model = MethodModels.get(TypeKind.STR, "startswith")
        assert model is not None
        assert model.return_type.kind == TypeKind.BOOL

    def test_endswith_returns_bool(self):
        model = MethodModels.get(TypeKind.STR, "endswith")
        assert model is not None
        assert model.return_type.kind == TypeKind.BOOL

    def test_encode_returns_bytes(self):
        model = MethodModels.get(TypeKind.STR, "encode")
        assert model is not None
        assert model.return_type.kind == TypeKind.BYTES
        assert "UnicodeEncodeError" in model.may_raise

    def test_format_returns_str(self):
        model = MethodModels.get(TypeKind.STR, "format")
        assert model is not None
        assert model.return_type.kind == TypeKind.STR

    def test_isalpha_returns_bool(self):
        model = MethodModels.get(TypeKind.STR, "isalpha")
        assert model is not None
        assert model.return_type.kind == TypeKind.BOOL
        assert model.is_pure

    def test_isdigit_returns_bool(self):
        model = MethodModels.get(TypeKind.STR, "isdigit")
        assert model is not None
        assert model.return_type.kind == TypeKind.BOOL

    def test_replace_returns_str(self):
        model = MethodModels.get(TypeKind.STR, "replace")
        assert model is not None
        assert model.return_type.kind == TypeKind.STR
        assert len(model.parameters) == 3
        assert model.parameters[2].has_default

    def test_capitalize_returns_str(self):
        model = MethodModels.get(TypeKind.STR, "capitalize")
        assert model is not None
        assert model.return_type.kind == TypeKind.STR

    def test_count_returns_int(self):
        model = MethodModels.get(TypeKind.STR, "count")
        assert model is not None
        assert model.return_type.kind == TypeKind.INT


# ===================================================================
# List method models
# ===================================================================


class TestListMethodModels:
    """Tests for list method models."""

    def test_append_exists(self):
        model = MethodModels.get(TypeKind.LIST, "append")
        assert model is not None

    def test_append_not_pure(self):
        model = MethodModels.get(TypeKind.LIST, "append")
        assert not model.is_pure
        assert not model.is_readonly

    def test_append_mutates_self(self):
        model = MethodModels.get(TypeKind.LIST, "append")
        assert "self" in model.mutates_parameters

    def test_append_returns_none(self):
        model = MethodModels.get(TypeKind.LIST, "append")
        assert model.return_type.kind == TypeKind.NONE

    def test_pop_may_raise(self):
        model = MethodModels.get(TypeKind.LIST, "pop")
        assert model is not None
        assert "IndexError" in model.may_raise

    def test_remove_may_raise(self):
        model = MethodModels.get(TypeKind.LIST, "remove")
        assert model is not None
        assert "ValueError" in model.may_raise

    def test_sort_mutates(self):
        model = MethodModels.get(TypeKind.LIST, "sort")
        assert model is not None
        assert not model.is_pure
        assert "self" in model.mutates_parameters

    def test_copy_is_pure(self):
        model = MethodModels.get(TypeKind.LIST, "copy")
        assert model is not None
        assert model.is_pure
        assert model.return_type.kind == TypeKind.LIST

    def test_index_returns_int(self):
        model = MethodModels.get(TypeKind.LIST, "index")
        assert model is not None
        assert model.return_type.kind == TypeKind.INT
        assert "ValueError" in model.may_raise

    def test_count_returns_int(self):
        model = MethodModels.get(TypeKind.LIST, "count")
        assert model is not None
        assert model.return_type.kind == TypeKind.INT

    def test_extend_mutates(self):
        model = MethodModels.get(TypeKind.LIST, "extend")
        assert model is not None
        assert "self" in model.mutates_parameters

    def test_clear_mutates(self):
        model = MethodModels.get(TypeKind.LIST, "clear")
        assert model is not None
        assert "self" in model.mutates_parameters


# ===================================================================
# Dict method models
# ===================================================================


class TestDictMethodModels:
    """Tests for dict method models."""

    def test_get_exists(self):
        model = MethodModels.get(TypeKind.DICT, "get")
        assert model is not None

    def test_get_is_pure(self):
        model = MethodModels.get(TypeKind.DICT, "get")
        assert model.is_pure
        assert model.is_readonly

    def test_pop_may_raise(self):
        model = MethodModels.get(TypeKind.DICT, "pop")
        assert model is not None
        assert "KeyError" in model.may_raise

    def test_popitem_may_raise(self):
        model = MethodModels.get(TypeKind.DICT, "popitem")
        assert model is not None
        assert "KeyError" in model.may_raise

    def test_keys_returns_dict_keys(self):
        model = MethodModels.get(TypeKind.DICT, "keys")
        assert model is not None
        assert model.return_type.kind == TypeKind.DICT_KEYS

    def test_values_returns_dict_values(self):
        model = MethodModels.get(TypeKind.DICT, "values")
        assert model is not None
        assert model.return_type.kind == TypeKind.DICT_VALUES

    def test_items_returns_dict_items(self):
        model = MethodModels.get(TypeKind.DICT, "items")
        assert model is not None
        assert model.return_type.kind == TypeKind.DICT_ITEMS

    def test_update_mutates(self):
        model = MethodModels.get(TypeKind.DICT, "update")
        assert model is not None
        assert "self" in model.mutates_parameters

    def test_copy_is_pure(self):
        model = MethodModels.get(TypeKind.DICT, "copy")
        assert model is not None
        assert model.is_pure
        assert model.return_type.kind == TypeKind.DICT

    def test_clear_mutates(self):
        model = MethodModels.get(TypeKind.DICT, "clear")
        assert model is not None
        assert "self" in model.mutates_parameters

    def test_setdefault_mutates(self):
        model = MethodModels.get(TypeKind.DICT, "setdefault")
        assert model is not None
        assert not model.is_pure


# ===================================================================
# Set method models
# ===================================================================


class TestSetMethodModels:
    """Tests for set method models."""

    def test_add_mutates(self):
        model = MethodModels.get(TypeKind.SET, "add")
        assert model is not None
        assert "self" in model.mutates_parameters

    def test_remove_may_raise(self):
        model = MethodModels.get(TypeKind.SET, "remove")
        assert model is not None
        assert "KeyError" in model.may_raise

    def test_discard_no_raise(self):
        model = MethodModels.get(TypeKind.SET, "discard")
        assert model is not None
        assert not model.may_raise

    def test_pop_may_raise(self):
        model = MethodModels.get(TypeKind.SET, "pop")
        assert model is not None
        assert "KeyError" in model.may_raise

    def test_union_is_pure(self):
        model = MethodModels.get(TypeKind.SET, "union")
        assert model is not None
        assert model.is_pure
        assert model.return_type.kind == TypeKind.SET

    def test_intersection_is_pure(self):
        model = MethodModels.get(TypeKind.SET, "intersection")
        assert model is not None
        assert model.is_pure

    def test_issubset_returns_bool(self):
        model = MethodModels.get(TypeKind.SET, "issubset")
        assert model is not None
        assert model.return_type.kind == TypeKind.BOOL

    def test_update_mutates(self):
        model = MethodModels.get(TypeKind.SET, "update")
        assert model is not None
        assert "self" in model.mutates_parameters

    def test_copy_is_pure(self):
        model = MethodModels.get(TypeKind.SET, "copy")
        assert model is not None
        assert model.is_pure
        assert model.return_type.kind == TypeKind.SET


# ===================================================================
# MethodModels.get() miss behavior
# ===================================================================


class TestMethodModelsGet:
    """Tests for MethodModels.get() with unknown methods."""

    def test_unknown_method_returns_none(self):
        model = MethodModels.get(TypeKind.STR, "nonexistent_method_xyz")
        assert model is None

    def test_unknown_type_returns_none(self):
        model = MethodModels.get(TypeKind.NONE, "something")
        assert model is None

    def test_get_returns_function_summary(self):
        model = MethodModels.get(TypeKind.STR, "upper")
        assert isinstance(model, FunctionSummary)

    def test_model_has_name(self):
        model = MethodModels.get(TypeKind.STR, "upper")
        assert model.name == "str.upper"
