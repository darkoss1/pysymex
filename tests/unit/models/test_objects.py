from __future__ import annotations

import pytest
import z3

import pysymex.models.objects as objects


class TestMethodType:
    """Test suite for pysymex.models.objects.MethodType."""

    def test_faithfulness(self) -> None:
        assert objects.MethodType.INSTANCE.name == "INSTANCE"

    def test_error_path(self) -> None:
        with pytest.raises(KeyError):
            _ = objects.MethodType["MISSING"]


class TestSymbolicAttribute:
    """Test suite for pysymex.models.objects.SymbolicAttribute."""

    def test_faithfulness(self) -> None:
        attr = objects.SymbolicAttribute(name="x", value=1, is_class_attr=True)
        updated = attr.with_value(2)
        assert updated.name == "x"
        assert updated.value == 2
        assert updated.is_class_attr is True

    def test_error_path(self) -> None:
        attr = objects.SymbolicAttribute(name="x", value=1)
        with pytest.raises(AttributeError):
            setattr(attr, "value", 3)


class TestSymbolicMethod:
    """Test suite for pysymex.models.objects.SymbolicMethod."""

    def test_faithfulness(self) -> None:
        method = objects.SymbolicMethod(name="m", parameters=["self"])
        assert method.name == "m"
        assert method.parameters == ["self"]

    def test_error_path(self) -> None:
        method = objects.SymbolicMethod(name="m", preconditions=[])
        assert method.func is None


class TestSymbolicClass:
    """Test suite for pysymex.models.objects.SymbolicClass."""

    def test_faithfulness(self) -> None:
        base = objects.SymbolicClass(name="Base")
        child = objects.SymbolicClass(name="Child", bases=[base])
        child.add_method("run")
        child.add_class_attr("kind", "child")
        assert child.has_method("run")
        assert child.get_method("run") is not None
        assert child.get_attribute("kind") is not None
        assert child.is_subclass_of(base)
        assert child.mro[0].name == "Child"

    def test_error_path(self) -> None:
        cls = objects.SymbolicClass(name="Only")
        assert cls.get_method("missing") is None
        assert cls.get_attribute("missing") is None


class TestSymbolicInstance:
    """Test suite for pysymex.models.objects.SymbolicInstance."""

    def test_faithfulness(self) -> None:
        def _ping(_: objects.SymbolicInstance) -> str:
            return "pong"

        cls = objects.SymbolicClass(name="User")
        cls.add_class_attr("kind", "user")
        cls.add_method("ping", _ping)
        inst = objects.SymbolicInstance(cls=cls, instance_id=7)
        inst.set_attr("x", 10)
        assert isinstance(inst.z3_id, z3.ArithRef)
        assert inst.get_attr("x") == 10
        assert inst.get_attr("kind") == "user"
        assert isinstance(inst.get_attr("ping"), objects.BoundMethod)
        assert inst.has_attr("x")
        assert inst.del_attr("x") is True

    def test_error_path(self) -> None:
        cls = objects.SymbolicClass(name="User")
        inst = objects.SymbolicInstance(cls=cls, instance_id=1)
        assert inst.get_attr("missing") is None
        assert inst.del_attr("missing") is False


class TestBoundMethod:
    """Test suite for pysymex.models.objects.BoundMethod."""

    def test_faithfulness(self) -> None:
        cls = objects.SymbolicClass(name="A")
        inst = objects.SymbolicInstance(cls=cls, instance_id=0)

        def _f(self: objects.SymbolicInstance, value: int) -> int:
            return self.instance_id + value

        method = objects.SymbolicMethod(name="f", func=_f)
        bound = objects.BoundMethod(instance=inst, method=method)
        assert bound(5) == 5

    def test_error_path(self) -> None:
        cls = objects.SymbolicClass(name="A")
        inst = objects.SymbolicInstance(cls=cls, instance_id=0)
        method = objects.SymbolicMethod(name="f", func=None)
        bound = objects.BoundMethod(instance=inst, method=method)
        assert bound() is None


class TestClassRegistry:
    """Test suite for pysymex.models.objects.ClassRegistry."""

    def test_faithfulness(self) -> None:
        registry = objects.ClassRegistry()
        cls = objects.SymbolicClass(name="Thing", module="m")
        registry.register_class(cls)
        fetched = registry.get_class("Thing", "m")
        assert fetched is cls
        instance = registry.create_instance(cls, {"a": 1})
        assert instance.attrs["a"] == 1
        assert registry.get_builtin("int") is not None

    def test_error_path(self) -> None:
        registry = objects.ClassRegistry()
        assert registry.get_class("Unknown", "x") is None
        assert registry.get_builtin("Unknown") is None


class TestTypeChecker:
    """Test suite for pysymex.models.objects.TypeChecker."""

    def test_faithfulness(self) -> None:
        registry = objects.ClassRegistry()
        checker = objects.TypeChecker(registry)
        int_cls = registry.get_builtin("int")
        object_cls = registry.get_builtin("object")
        assert int_cls is not None
        assert object_cls is not None
        assert z3.is_true(checker.isinstance_check(7, int_cls))
        assert z3.is_true(checker.issubclass_check(int_cls, object_cls))
        assert checker.type_of(1.0) is registry.get_builtin("float")

    def test_error_path(self) -> None:
        registry = objects.ClassRegistry()
        checker = objects.TypeChecker(registry)
        int_cls = registry.get_builtin("int")
        assert int_cls is not None
        assert z3.is_false(checker.isinstance_check(object(), int_cls))
        assert checker.type_of(object()) is registry.get_builtin("object")


class TestSymbolicDescriptor:
    """Test suite for pysymex.models.objects.SymbolicDescriptor."""

    def test_faithfulness(self) -> None:
        descriptor = objects.SymbolicDescriptor()
        cls = objects.SymbolicClass(name="A")
        inst = objects.SymbolicInstance(cls=cls, instance_id=0)
        with pytest.raises(NotImplementedError):
            descriptor.__get__(inst, cls)

    def test_error_path(self) -> None:
        descriptor = objects.SymbolicDescriptor()
        cls = objects.SymbolicClass(name="A")
        inst = objects.SymbolicInstance(cls=cls, instance_id=0)
        with pytest.raises(NotImplementedError):
            descriptor.__set__(inst, 1)
        with pytest.raises(NotImplementedError):
            descriptor.__delete__(inst)


class TestSymbolicProperty:
    """Test suite for pysymex.models.objects.SymbolicProperty."""

    def test_faithfulness(self) -> None:
        cls = objects.SymbolicClass(name="A")
        inst = objects.SymbolicInstance(cls=cls, instance_id=0)

        def _get(instance: objects.SymbolicInstance) -> int:
            return instance.instance_id

        prop = objects.SymbolicProperty(fget=_get)
        assert prop.__get__(inst, cls) == 0
        assert prop.__get__(None, cls) is prop

    def test_error_path(self) -> None:
        cls = objects.SymbolicClass(name="A")
        inst = objects.SymbolicInstance(cls=cls, instance_id=0)
        prop = objects.SymbolicProperty()
        with pytest.raises(AttributeError):
            prop.__get__(inst, cls)
        with pytest.raises(AttributeError):
            prop.__set__(inst, 1)
        with pytest.raises(AttributeError):
            prop.__delete__(inst)
