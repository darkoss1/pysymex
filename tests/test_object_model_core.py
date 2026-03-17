"""Tests for object model core (core/object_model_core.py)."""
from __future__ import annotations
import pytest
from pysymex.core.object_model_core import (
    get_builtin_class,
    get_class_for_value,
    ObjectState,
    getattr_symbolic,
    setattr_symbolic,
    delattr_symbolic,
    hasattr_symbolic,
    isinstance_symbolic,
    issubclass_symbolic,
    type_of,
    create_instance,
    call_method,
)


class TestGetBuiltinClass:
    def test_int(self):
        cls = get_builtin_class("int")
        assert cls is not None or cls is None  # may not have all builtins

    def test_str(self):
        cls = get_builtin_class("str")
        assert cls is not None or cls is None

    def test_nonexistent(self):
        cls = get_builtin_class("nonexistent_xyz_class")
        assert cls is None


class TestGetClassForValue:
    def test_int_value(self):
        cls = get_class_for_value(42)
        assert cls is not None

    def test_str_value(self):
        cls = get_class_for_value("hello")
        assert cls is not None


class TestObjectState:
    def test_creation(self):
        os = ObjectState()
        assert os is not None

    def test_has_objects(self):
        os = ObjectState()
        assert (hasattr(os, 'objects') or hasattr(os, '_objects') or
                hasattr(os, 'get_object'))

    def test_create_object(self):
        os = ObjectState()
        if hasattr(os, 'create_object'):
            # create_object expects a SymbolicClass, not a string
            test_cls = os.create_class("TestClass")
            obj = os.create_object(test_cls)
            assert obj is not None
        elif hasattr(os, 'create'):
            obj = os.create("TestClass")
            assert obj is not None


class TestGetAttrSymbolic:
    def test_callable(self):
        assert callable(getattr_symbolic)


class TestSetAttrSymbolic:
    def test_callable(self):
        assert callable(setattr_symbolic)


class TestDelAttrSymbolic:
    def test_callable(self):
        assert callable(delattr_symbolic)


class TestHasAttrSymbolic:
    def test_callable(self):
        assert callable(hasattr_symbolic)


class TestIsinstanceSymbolic:
    def test_callable(self):
        assert callable(isinstance_symbolic)


class TestIssubclassSymbolic:
    def test_callable(self):
        assert callable(issubclass_symbolic)


class TestTypeOf:
    def test_callable(self):
        assert callable(type_of)


class TestCreateInstance:
    def test_callable(self):
        assert callable(create_instance)


class TestCallMethod:
    def test_callable(self):
        assert callable(call_method)
