"""Tests for pysymex.core.oop_support — Enhanced OOP class/object/method system.

Covers: MethodType, EnhancedMethod, InitParameter, EnhancedClass,
EnhancedObject, EnhancedClassRegistry, EnhancedSuper,
create_enhanced_instance, register_enhanced_class, get_enhanced_class,
extract_init_params, make_dataclass, is_dataclass.
"""

from __future__ import annotations

import pytest

from pysymex.core.object_model import (
    OBJECT_CLASS,
    ObjectState,
    SymbolicClass,
    SymbolicMethod,
    SymbolicObject,
    SymbolicProperty,
)
from pysymex.core.oop_support import (
    EnhancedClass,
    EnhancedClassRegistry,
    EnhancedMethod,
    EnhancedObject,
    EnhancedSuper,
    InitParameter,
    MethodType,
    create_enhanced_instance,
    extract_init_params,
    get_enhanced_class,
    is_dataclass,
    make_dataclass,
    register_enhanced_class,
)
from pysymex.core.types import SymbolicValue


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_enhanced_class(name: str = "MyClass") -> EnhancedClass:
    """Register and return a fresh EnhancedClass."""
    registry = EnhancedClassRegistry()
    return registry.register_class(name)


def _dummy_func(*args, **kwargs):
    """A do-nothing function used as method placeholder."""
    pass


# ---------------------------------------------------------------------------
# MethodType enum
# ---------------------------------------------------------------------------

class TestMethodType:

    def test_instance(self):
        assert MethodType.INSTANCE is not None

    def test_class(self):
        assert MethodType.CLASS is not None

    def test_static(self):
        assert MethodType.STATIC is not None

    def test_property(self):
        assert MethodType.PROPERTY is not None

    def test_abstract(self):
        assert MethodType.ABSTRACT is not None

    def test_values_distinct(self):
        values = [m.value for m in MethodType]
        assert len(values) == len(set(values))


# ---------------------------------------------------------------------------
# EnhancedMethod
# ---------------------------------------------------------------------------

class TestEnhancedMethod:

    def test_basic_creation(self):
        m = EnhancedMethod(func=_dummy_func, name="foo")
        assert m.name == "foo"
        assert m.method_type == MethodType.INSTANCE

    def test_is_bound_false_initially(self):
        m = EnhancedMethod(func=_dummy_func, name="foo")
        assert m.is_bound is False

    def test_bind_to_instance(self):
        ec = _make_enhanced_class()
        obj_state = ObjectState()
        obj = obj_state.create_object(ec.base)
        m = EnhancedMethod(func=_dummy_func, name="foo", owner=ec.base)
        bound = m.bind_to_instance(obj)
        assert bound.is_bound is True
        assert bound.bound_to is obj

    def test_bind_static_returns_self(self):
        m = EnhancedMethod(func=_dummy_func, name="foo", method_type=MethodType.STATIC)
        obj_state = ObjectState()
        ec = _make_enhanced_class()
        obj = obj_state.create_object(ec.base)
        bound = m.bind_to_instance(obj)
        assert bound is m  # Static methods don't bind

    def test_bind_classmethod_to_instance(self):
        ec = _make_enhanced_class()
        obj_state = ObjectState()
        obj = obj_state.create_object(ec.base)
        m = EnhancedMethod(func=_dummy_func, name="foo", method_type=MethodType.CLASS)
        bound = m.bind_to_instance(obj)
        assert bound.bound_to is obj.cls

    def test_bind_to_class(self):
        ec = _make_enhanced_class()
        m = EnhancedMethod(func=_dummy_func, name="foo", method_type=MethodType.CLASS)
        bound = m.bind_to_class(ec.base)
        assert bound.bound_to is ec.base

    def test_get_call_args_static(self):
        m = EnhancedMethod(func=_dummy_func, method_type=MethodType.STATIC)
        args, kwargs = m.get_call_args((1, 2), {"k": 3})
        assert args == (1, 2)
        assert kwargs == {"k": 3}

    def test_get_call_args_classmethod_bound(self):
        ec = _make_enhanced_class()
        m = EnhancedMethod(func=_dummy_func, method_type=MethodType.CLASS, bound_to=ec.base)
        args, kwargs = m.get_call_args((1,), {})
        assert args[0] is ec.base
        assert args[1] == 1

    def test_get_call_args_instance_bound(self):
        ec = _make_enhanced_class()
        obj_state = ObjectState()
        obj = obj_state.create_object(ec.base)
        m = EnhancedMethod(func=_dummy_func, method_type=MethodType.INSTANCE, bound_to=obj)
        args, kwargs = m.get_call_args((1,), {})
        assert args[0] is obj
        assert args[1] == 1

    def test_get_call_args_unbound(self):
        m = EnhancedMethod(func=_dummy_func, method_type=MethodType.INSTANCE)
        args, kwargs = m.get_call_args((1,), {})
        assert args == (1,)


# ---------------------------------------------------------------------------
# InitParameter
# ---------------------------------------------------------------------------

class TestInitParameter:

    def test_basic_creation(self):
        p = InitParameter(name="x")
        assert p.name == "x"
        assert p.has_default is False
        assert p.is_self is False

    def test_self_parameter(self):
        p = InitParameter(name="self", is_self=True)
        assert p.is_self is True

    def test_to_symbolic_self_returns_none(self):
        p = InitParameter(name="self", is_self=True)
        assert p.to_symbolic(0) is None

    def test_to_symbolic_int_hint(self):
        p = InitParameter(name="x", type_hint="int")
        result = p.to_symbolic(0)
        assert isinstance(result, SymbolicValue)

    def test_to_symbolic_bool_hint(self):
        p = InitParameter(name="b", type_hint="bool")
        result = p.to_symbolic(0)
        assert isinstance(result, SymbolicValue)

    def test_to_symbolic_with_default(self):
        p = InitParameter(name="x", has_default=True, default=42)
        result = p.to_symbolic(0)
        assert result == 42

    def test_to_symbolic_no_hint_no_default(self):
        p = InitParameter(name="x")
        result = p.to_symbolic(0)
        assert isinstance(result, SymbolicValue)


# ---------------------------------------------------------------------------
# EnhancedClass
# ---------------------------------------------------------------------------

class TestEnhancedClass:

    def test_name_property(self):
        ec = _make_enhanced_class("Foo")
        assert ec.name == "Foo"

    def test_qualname_property(self):
        ec = _make_enhanced_class("Bar")
        assert ec.qualname == "Bar"

    def test_is_abstract_false_by_default(self):
        ec = _make_enhanced_class()
        assert ec.is_abstract is False

    def test_add_method_instance(self):
        ec = _make_enhanced_class()
        ec.add_method("do_thing", _dummy_func)
        assert "do_thing" in ec.methods

    def test_add_method_class(self):
        ec = _make_enhanced_class()
        ec.add_method("cls_method", _dummy_func, method_type=MethodType.CLASS)
        assert "cls_method" in ec.class_methods

    def test_add_method_static(self):
        ec = _make_enhanced_class()
        ec.add_method("static_method", _dummy_func, method_type=MethodType.STATIC)
        assert "static_method" in ec.static_methods

    def test_add_method_property(self):
        ec = _make_enhanced_class()
        ec.add_method("prop", _dummy_func, method_type=MethodType.PROPERTY)
        assert "prop" in ec.properties

    def test_add_method_abstract(self):
        ec = _make_enhanced_class()
        ec.add_method("abstract_m", _dummy_func, method_type=MethodType.ABSTRACT)
        assert "abstract_m" in ec.abstract_methods
        assert ec.is_abstract is True

    def test_add_property(self):
        ec = _make_enhanced_class()
        ec.add_property("my_prop", fget=_dummy_func)
        assert "my_prop" in ec.properties

    def test_set_init_params(self):
        ec = _make_enhanced_class()
        params = [
            InitParameter(name="self", is_self=True),
            InitParameter(name="x"),
            InitParameter(name="y", has_default=True, default=0),
        ]
        ec.set_init_params(params)
        assert ec.required_init_args == 1  # only "x" is required

    def test_get_method_instance(self):
        ec = _make_enhanced_class()
        ec.add_method("foo", _dummy_func)
        m = ec.get_method("foo")
        assert m is not None
        assert m.name == "foo"

    def test_get_method_class(self):
        ec = _make_enhanced_class()
        ec.add_method("bar", _dummy_func, method_type=MethodType.CLASS)
        m = ec.get_method("bar")
        assert m is not None

    def test_get_method_static(self):
        ec = _make_enhanced_class()
        ec.add_method("baz", _dummy_func, method_type=MethodType.STATIC)
        m = ec.get_method("baz")
        assert m is not None

    def test_get_method_missing(self):
        ec = _make_enhanced_class()
        assert ec.get_method("nonexistent") is None


# ---------------------------------------------------------------------------
# EnhancedObject
# ---------------------------------------------------------------------------

class TestEnhancedObject:

    def test_creation(self):
        ec = _make_enhanced_class()
        obj_state = ObjectState()
        base_obj = obj_state.create_object(ec.base)
        eo = EnhancedObject(base=base_obj, enhanced_class=ec)
        assert eo.initialized is False
        assert eo.cls is ec.base

    def test_set_and_get_attribute(self):
        ec = _make_enhanced_class()
        obj_state = ObjectState()
        base_obj = obj_state.create_object(ec.base)
        eo = EnhancedObject(base=base_obj, enhanced_class=ec)
        ok = eo.set_attribute("x", 42)
        assert ok is True
        val, found = eo.get_attribute("x")
        assert found is True
        assert val == 42

    def test_set_attribute_slots_restriction(self):
        ec = _make_enhanced_class()
        ec.slots = ("allowed",)
        obj_state = ObjectState()
        base_obj = obj_state.create_object(ec.base)
        eo = EnhancedObject(base=base_obj, enhanced_class=ec)
        assert eo.set_attribute("allowed", 1) is True
        assert eo.set_attribute("disallowed", 2) is False

    def test_get_attribute_from_method(self):
        ec = _make_enhanced_class()
        ec.add_method("greet", _dummy_func)
        obj_state = ObjectState()
        base_obj = obj_state.create_object(ec.base)
        eo = EnhancedObject(base=base_obj, enhanced_class=ec)
        val, found = eo.get_attribute("greet")
        assert found is True
        assert isinstance(val, EnhancedMethod)

    def test_get_attribute_missing(self):
        ec = _make_enhanced_class()
        obj_state = ObjectState()
        base_obj = obj_state.create_object(ec.base)
        eo = EnhancedObject(base=base_obj, enhanced_class=ec)
        val, found = eo.get_attribute("nonexistent")
        assert found is False
        assert val is None

    def test_call_method(self):
        ec = _make_enhanced_class()
        ec.add_method("do_it", _dummy_func)
        obj_state = ObjectState()
        base_obj = obj_state.create_object(ec.base)
        eo = EnhancedObject(base=base_obj, enhanced_class=ec)
        result, found = eo.call_method("do_it")
        assert found is True
        assert isinstance(result, SymbolicValue)

    def test_call_method_missing(self):
        ec = _make_enhanced_class()
        obj_state = ObjectState()
        base_obj = obj_state.create_object(ec.base)
        eo = EnhancedObject(base=base_obj, enhanced_class=ec)
        result, found = eo.call_method("nonexistent")
        assert found is False
        assert result is None

    def test_id_property(self):
        ec = _make_enhanced_class()
        obj_state = ObjectState()
        base_obj = obj_state.create_object(ec.base)
        eo = EnhancedObject(base=base_obj, enhanced_class=ec)
        assert eo.id == base_obj.id


# ---------------------------------------------------------------------------
# EnhancedClassRegistry
# ---------------------------------------------------------------------------

class TestEnhancedClassRegistry:

    def test_register_and_get(self):
        reg = EnhancedClassRegistry()
        ec = reg.register_class("TestClass")
        assert ec is not None
        assert reg.get_class("TestClass") is ec

    def test_get_missing(self):
        reg = EnhancedClassRegistry()
        assert reg.get_class("NoSuch") is None

    def test_list_classes(self):
        reg = EnhancedClassRegistry()
        reg.register_class("A")
        reg.register_class("B")
        names = reg.list_classes()
        assert "A" in names
        assert "B" in names

    def test_register_by_code(self):
        reg = EnhancedClassRegistry()
        ec = reg.register_class("Coded")
        reg.register_by_code(12345, ec)
        assert reg.get_by_code(12345) is ec

    def test_get_by_code_missing(self):
        reg = EnhancedClassRegistry()
        assert reg.get_by_code(99999) is None

    def test_default_base_is_object(self):
        reg = EnhancedClassRegistry()
        ec = reg.register_class("Child")
        assert ec.base.bases == (OBJECT_CLASS,)


# ---------------------------------------------------------------------------
# create_enhanced_instance
# ---------------------------------------------------------------------------

class TestCreateEnhancedInstance:

    def test_basic_instance_creation(self):
        ec = _make_enhanced_class()
        obj_state = ObjectState()
        instance, constraints = create_enhanced_instance(ec, obj_state)
        assert isinstance(instance, EnhancedObject)
        assert instance.initialized is True

    def test_instance_with_args(self):
        ec = _make_enhanced_class()
        ec.set_init_params([
            InitParameter(name="self", is_self=True),
            InitParameter(name="x"),
        ])
        obj_state = ObjectState()
        instance, constraints = create_enhanced_instance(ec, obj_state, args=(42,))
        assert instance.init_values.get("x") == 42

    def test_instance_with_kwargs(self):
        ec = _make_enhanced_class()
        ec.set_init_params([
            InitParameter(name="self", is_self=True),
            InitParameter(name="name"),
        ])
        obj_state = ObjectState()
        instance, _ = create_enhanced_instance(ec, obj_state, kwargs={"name": "test"})
        assert instance.init_values.get("name") == "test"

    def test_instance_with_default(self):
        ec = _make_enhanced_class()
        ec.set_init_params([
            InitParameter(name="self", is_self=True),
            InitParameter(name="x", has_default=True, default=99),
        ])
        obj_state = ObjectState()
        instance, _ = create_enhanced_instance(ec, obj_state)
        assert instance.init_values.get("x") == 99

    def test_abstract_class_raises(self):
        ec = _make_enhanced_class()
        ec.add_method("do_thing", _dummy_func, method_type=MethodType.ABSTRACT)
        obj_state = ObjectState()
        with pytest.raises(TypeError, match="abstract"):
            create_enhanced_instance(ec, obj_state)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

class TestModuleFunctions:

    def test_register_enhanced_class(self):
        ec = register_enhanced_class("GlobalTestClass_unique_42")
        assert ec is not None
        assert ec.name == "GlobalTestClass_unique_42"

    def test_get_enhanced_class(self):
        register_enhanced_class("LookupTest_unique_43")
        ec = get_enhanced_class("LookupTest_unique_43")
        assert ec is not None

    def test_get_enhanced_class_missing(self):
        result = get_enhanced_class("definitely_not_registered_xyz")
        assert result is None


# ---------------------------------------------------------------------------
# extract_init_params
# ---------------------------------------------------------------------------

class TestExtractInitParams:

    def test_with_real_code_object(self):
        def sample_init(self, x, y=10):
            pass

        params = extract_init_params(sample_init.__code__)
        assert len(params) >= 2
        names = [p.name for p in params]
        assert "self" in names or "x" in names

    def test_non_code_object(self):
        params = extract_init_params("not_a_code_object")
        assert params == []


# ---------------------------------------------------------------------------
# make_dataclass / is_dataclass
# ---------------------------------------------------------------------------

class TestMakeDataclass:

    def test_is_dataclass_false_by_default(self):
        ec = _make_enhanced_class()
        assert is_dataclass(ec) is False

    def test_make_dataclass_sets_flag(self):
        ec = _make_enhanced_class()
        make_dataclass(ec, {"x": ("int", None), "y": ("str", "hello")})
        assert is_dataclass(ec) is True

    def test_make_dataclass_sets_fields(self):
        ec = _make_enhanced_class()
        fields = {"a": ("int", None), "b": ("str", "default")}
        make_dataclass(ec, fields)
        assert ec.dataclass_fields == fields

    def test_make_dataclass_creates_init_params(self):
        ec = _make_enhanced_class()
        make_dataclass(ec, {"x": ("int", None), "y": ("str", "hello")})
        assert len(ec.init_params) == 3  # self + x + y
        assert ec.init_params[0].is_self is True
        assert ec.init_params[1].name == "x"
        assert ec.init_params[2].name == "y"
        assert ec.init_params[2].has_default is True
