from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.calls.payload import (
    MethodDescriptorPayload,
    SymbolicFunctionPayload,
)
from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.descriptors import SymbolicDescriptor, SymbolicProperty
from pysymex._internal.core.classes.instances import BoundMethod, SymbolicInstance
from pysymex._internal.core.classes.registry import ClassRegistry
from pysymex._internal.core.classes.types import MethodType, SymbolicAttribute, SymbolicMethod
from pysymex._internal.core.types.scalars.values import SymbolicValue


class TestMethodType:
    """Test suite for pysymex._internal.core.classes.MethodType."""

    def test_faithfulness(self) -> None:
        assert MethodType.INSTANCE.name == "INSTANCE"

    def test_error_path(self) -> None:
        with pytest.raises(KeyError):
            _ = MethodType["MISSING"]


class TestSymbolicAttribute:
    """Test suite for pysymex._internal.core.classes.SymbolicAttribute."""

    def test_faithfulness(self) -> None:
        attr = SymbolicAttribute(name="x", value=1, is_class_attr=True)
        updated = attr.with_value(2)
        assert updated.name == "x"
        assert updated.value == 2
        assert updated.is_class_attr is True

    def test_error_path(self) -> None:
        attr = SymbolicAttribute(name="x", value=1)
        with pytest.raises(AttributeError):
            setattr(attr, "value", 3)


class TestSymbolicMethod:
    """Test suite for pysymex._internal.core.classes.SymbolicMethod."""

    def test_faithfulness(self) -> None:
        method = SymbolicMethod(name="m", parameters=["self"])
        assert method.name == "m"
        assert method.parameters == ["self"]

    def test_error_path(self) -> None:
        method = SymbolicMethod(name="m", preconditions=[])
        assert method.func is None


class TestSymbolicClass:
    """Test suite for pysymex._internal.core.classes.SymbolicClass."""

    def test_faithfulness(self) -> None:
        base = SymbolicClass(name="Base")
        child = SymbolicClass(name="Child", bases=[base])
        child.add_method("run")
        child.add_class_attr("kind", "child")
        assert child.has_method("run")
        assert child.get_method("run") is not None
        assert child.get_attribute("kind") is not None
        assert child.is_subclass_of(base)
        assert child.mro[0].name == "Child"

    def test_error_path(self) -> None:
        cls = SymbolicClass(name="Only")
        assert cls.get_method("missing") is None
        assert cls.get_attribute("missing") is None

    def test_abstract_methods_are_resolved_by_concrete_override(self) -> None:
        """Inherited abstract methods block only subclasses without an override."""
        base = SymbolicClass(name="Base")
        base.add_method("run", method_type=MethodType.ABSTRACT)
        incomplete = SymbolicClass(name="Incomplete", bases=[base])
        concrete = SymbolicClass(name="Concrete", bases=[base])
        concrete.add_method("run")

        assert base.is_abstract is True
        assert incomplete.is_abstract is True
        assert concrete.is_abstract is False

    def test_symbolic_function_class_attribute_becomes_instance_method(self) -> None:
        """Runtime class writes of Python functions preserve descriptor binding."""

        def replacement(self: object, value: int) -> int:
            _ = self
            return value

        function_value = SymbolicValue.symbolic("replacement")[0]
        function_value.attach_modeled_object(SymbolicFunctionPayload(replacement.__code__))
        cls = SymbolicClass(name="Decorated")

        cls.add_class_attr("replacement", function_value)

        assert cls.get_attribute("replacement") is None
        method = cls.get_method("replacement")
        assert method is not None
        assert method.parameters == ["self", "value"]

    def test_runtime_classmethod_descriptor_becomes_class_method(self) -> None:
        """Runtime ``classmethod(function)`` writes preserve class binding."""

        def replacement(cls: object, value: int) -> int:
            _ = cls
            return value

        descriptor_value = SymbolicValue.symbolic("replacement_classmethod")[0]
        descriptor_value.attach_modeled_object(
            MethodDescriptorPayload(
                payload=SymbolicFunctionPayload(replacement.__code__),
                kind="class",
            )
        )
        cls = SymbolicClass(name="Decorated")

        cls.add_class_attr("replacement", descriptor_value)

        assert cls.get_attribute("replacement") is None
        method = cls.get_method("replacement")
        assert method is not None
        assert method.method_type is MethodType.CLASS
        assert method.parameters == ["cls", "value"]

    def test_runtime_staticmethod_descriptor_becomes_static_method(self) -> None:
        """Runtime ``staticmethod(function)`` writes preserve static binding."""

        def replacement(value: int) -> int:
            return value

        descriptor_value = SymbolicValue.symbolic("replacement_staticmethod")[0]
        descriptor_value.attach_modeled_object(
            MethodDescriptorPayload(
                payload=SymbolicFunctionPayload(replacement.__code__),
                kind="static",
            )
        )
        cls = SymbolicClass(name="Decorated")

        cls.add_class_attr("replacement", descriptor_value)

        assert cls.get_attribute("replacement") is None
        method = cls.get_method("replacement")
        assert method is not None
        assert method.method_type is MethodType.STATIC
        assert method.parameters == ["value"]


class TestSymbolicInstance:
    """Test suite for pysymex._internal.core.classes.SymbolicInstance."""

    def test_faithfulness(self) -> None:
        def _ping(_: SymbolicInstance) -> str:
            return "pong"

        cls = SymbolicClass(name="User")
        cls.add_class_attr("kind", "user")
        cls.add_method("ping", _ping)
        inst = SymbolicInstance(cls=cls, instance_id=7)
        inst.set_attr("x", 10)
        assert isinstance(inst.z3_id, z3.ArithRef)
        assert inst.get_attr("x") == 10
        assert inst.get_attr("kind") == "user"
        assert isinstance(inst.get_attr("ping"), BoundMethod)
        assert inst.has_attr("x")
        assert inst.del_attr("x") is True

    def test_error_path(self) -> None:
        cls = SymbolicClass(name="User")
        inst = SymbolicInstance(cls=cls, instance_id=1)
        assert inst.get_attr("missing") is None
        assert inst.del_attr("missing") is False


class TestBoundMethod:
    """Test suite for pysymex._internal.core.classes.BoundMethod."""

    def test_faithfulness(self) -> None:
        cls = SymbolicClass(name="A")
        inst = SymbolicInstance(cls=cls, instance_id=0)

        def _f(self: SymbolicInstance, value: int) -> int:
            return self.instance_id + value

        method = SymbolicMethod(name="f", func=_f)
        bound = BoundMethod(instance=inst, method=method)
        assert bound(5) == 5

    def test_error_path(self) -> None:
        cls = SymbolicClass(name="A")
        inst = SymbolicInstance(cls=cls, instance_id=0)
        method = SymbolicMethod(name="f", func=None)
        bound = BoundMethod(instance=inst, method=method)
        assert bound() is None


class TestClassRegistry:
    """Test suite for pysymex._internal.core.classes.ClassRegistry."""

    def test_faithfulness(self) -> None:
        registry = ClassRegistry()
        cls = SymbolicClass(name="Thing", module="m")
        registry.register_class(cls)
        fetched = registry.get_class("Thing", "m")
        assert fetched is cls
        instance = registry.create_instance(cls, {"a": 1})
        assert instance.attrs["a"] == 1
        assert registry.get_builtin("int") is not None

    def test_error_path(self) -> None:
        registry = ClassRegistry()
        assert registry.get_class("Unknown", "x") is None
        assert registry.get_builtin("Unknown") is None


class TestSymbolicDescriptor:
    """Test suite for pysymex._internal.core.classes.SymbolicDescriptor."""

    def test_faithfulness(self) -> None:
        descriptor = SymbolicDescriptor()
        cls = SymbolicClass(name="A")
        inst = SymbolicInstance(cls=cls, instance_id=0)
        with pytest.raises(AttributeError):
            descriptor.__get__(inst, cls)

    def test_error_path(self) -> None:
        descriptor = SymbolicDescriptor()
        cls = SymbolicClass(name="A")
        inst = SymbolicInstance(cls=cls, instance_id=0)
        with pytest.raises(AttributeError):
            descriptor.__set__(inst, 1)
        with pytest.raises(AttributeError):
            descriptor.__delete__(inst)


class TestSymbolicProperty:
    """Test suite for pysymex._internal.core.classes.SymbolicProperty."""

    def test_faithfulness(self) -> None:
        cls = SymbolicClass(name="A")
        inst = SymbolicInstance(cls=cls, instance_id=0)

        def _get(instance: SymbolicInstance) -> int:
            return instance.instance_id

        prop = SymbolicProperty(fget=_get)
        assert prop.__get__(inst, cls) == 0
        assert prop.__get__(None, cls) is prop

    def test_error_path(self) -> None:
        cls = SymbolicClass(name="A")
        inst = SymbolicInstance(cls=cls, instance_id=0)
        prop = SymbolicProperty()
        with pytest.raises(AttributeError):
            prop.__get__(inst, cls)
        with pytest.raises(AttributeError):
            prop.__set__(inst, 1)
        with pytest.raises(AttributeError):
            prop.__delete__(inst)
