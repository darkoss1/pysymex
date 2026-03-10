"""Tests for OOP modeling."""

import pytest
import z3

from pysymex.models.objects import (
    BoundMethod,
    ClassRegistry,
    MethodType,
    SymbolicAttribute,
    SymbolicClass,
    SymbolicInstance,
    SymbolicMethod,
    SymbolicProperty,
    TypeChecker,
)


class TestSymbolicAttribute:
    """Tests for SymbolicAttribute."""

    def test_create_attribute(self):
        """Test creating an attribute."""
        attr = SymbolicAttribute(
            name="value",
            value=42,
            is_class_attr=False,
        )

        assert attr.name == "value"
        assert attr.value == 42
        assert not attr.is_class_attr

    def test_with_value(self):
        """Test creating copy with new value."""
        attr = SymbolicAttribute(name="x", value=1)
        new_attr = attr.with_value(2)

        assert attr.value == 1
        assert new_attr.value == 2
        assert attr.name == new_attr.name


class TestSymbolicMethod:
    """Tests for SymbolicMethod."""

    def test_create_instance_method(self):
        """Test creating an instance method."""
        method = SymbolicMethod(
            name="get_value",
            method_type=MethodType.INSTANCE,
            parameters=["self"],
        )

        assert method.name == "get_value"
        assert method.method_type == MethodType.INSTANCE

    def test_create_class_method(self):
        """Test creating a class method."""
        method = SymbolicMethod(
            name="from_string",
            method_type=MethodType.CLASS,
            parameters=["cls", "s"],
        )

        assert method.method_type == MethodType.CLASS

    def test_create_static_method(self):
        """Test creating a static method."""
        method = SymbolicMethod(
            name="utility",
            method_type=MethodType.STATIC,
        )

        assert method.method_type == MethodType.STATIC


class TestSymbolicClass:
    """Tests for SymbolicClass."""

    def test_create_simple_class(self):
        """Test creating a simple class."""
        cls = SymbolicClass(name="Point", module="geometry")

        assert cls.name == "Point"
        assert cls.module == "geometry"

    def test_add_method(self):
        """Test adding methods to a class."""
        cls = SymbolicClass(name="Counter")
        cls.add_method("increment")
        cls.add_method("decrement")

        assert "increment" in cls.methods
        assert "decrement" in cls.methods

    def test_add_class_attr(self):
        """Test adding class attributes."""
        cls = SymbolicClass(name="Config")
        cls.add_class_attr("DEFAULT_VALUE", 0)

        assert "DEFAULT_VALUE" in cls.class_attrs
        assert cls.class_attrs["DEFAULT_VALUE"].value == 0

    def test_inheritance(self):
        """Test class inheritance."""
        base = SymbolicClass(name="Animal")
        base.add_method("speak")

        derived = SymbolicClass(name="Dog", bases=[base])
        derived.add_method("bark")

        assert derived.is_subclass_of(base)
        assert not base.is_subclass_of(derived)

    def test_method_resolution_order(self):
        """Test MRO computation."""
        a = SymbolicClass(name="A")
        b = SymbolicClass(name="B", bases=[a])
        c = SymbolicClass(name="C", bases=[a])
        d = SymbolicClass(name="D", bases=[b, c])

        mro = d.mro

        assert d in mro
        assert a in mro
        # D should be first
        assert mro[0] == d

    def test_get_method_inherited(self):
        """Test getting inherited method."""
        base = SymbolicClass(name="Base")
        base.add_method("base_method")

        derived = SymbolicClass(name="Derived", bases=[base])

        method = derived.get_method("base_method")

        assert method is not None
        assert method.name == "base_method"

    def test_method_override(self):
        """Test method overriding."""
        base = SymbolicClass(name="Base")
        base.add_method("method", func=lambda self: "base")

        derived = SymbolicClass(name="Derived", bases=[base])
        derived.add_method("method", func=lambda self: "derived")

        base_method = base.get_method("method")
        derived_method = derived.get_method("method")

        assert base_method is not derived_method


class TestSymbolicInstance:
    """Tests for SymbolicInstance."""

    def test_create_instance(self):
        """Test creating an instance."""
        cls = SymbolicClass(name="Widget")
        instance = SymbolicInstance(cls=cls, instance_id=1)

        assert instance.cls == cls
        assert instance.instance_id == 1

    def test_get_set_attr(self):
        """Test getting and setting attributes."""
        cls = SymbolicClass(name="Point")
        instance = SymbolicInstance(cls=cls, instance_id=1)

        instance.set_attr("x", 10)
        instance.set_attr("y", 20)

        assert instance.get_attr("x") == 10
        assert instance.get_attr("y") == 20

    def test_get_class_attr(self):
        """Test getting class attribute from instance."""
        cls = SymbolicClass(name="Config")
        cls.add_class_attr("DEFAULT", 42)

        instance = SymbolicInstance(cls=cls, instance_id=1)

        assert instance.get_attr("DEFAULT") == 42

    def test_has_attr(self):
        """Test attribute existence check."""
        cls = SymbolicClass(name="Item")
        cls.add_method("process")

        instance = SymbolicInstance(cls=cls, instance_id=1)
        instance.set_attr("value", 1)

        assert instance.has_attr("value")
        assert instance.has_attr("process")
        assert not instance.has_attr("nonexistent")

    def test_del_attr(self):
        """Test deleting attribute."""
        cls = SymbolicClass(name="Obj")
        instance = SymbolicInstance(cls=cls, instance_id=1)

        instance.set_attr("x", 1)
        assert instance.has_attr("x")

        result = instance.del_attr("x")
        assert result
        assert not instance.has_attr("x")

    def test_isinstance_of(self):
        """Test isinstance check."""
        base = SymbolicClass(name="Base")
        derived = SymbolicClass(name="Derived", bases=[base])
        other = SymbolicClass(name="Other")

        instance = SymbolicInstance(cls=derived, instance_id=1)

        assert instance.isinstance_of(derived)
        assert instance.isinstance_of(base)
        assert not instance.isinstance_of(other)

    def test_z3_id(self):
        """Test Z3 object identity."""
        cls = SymbolicClass(name="Obj")
        i1 = SymbolicInstance(cls=cls, instance_id=1)
        i2 = SymbolicInstance(cls=cls, instance_id=2)

        assert i1.z3_id is not None
        assert i2.z3_id is not None

        # Different ids
        solver = z3.Solver()
        solver.add(i1.z3_id != i2.z3_id)
        assert solver.check() == z3.sat


class TestBoundMethod:
    """Tests for BoundMethod."""

    def test_create_bound_method(self):
        """Test creating a bound method."""
        cls = SymbolicClass(name="Obj")
        instance = SymbolicInstance(cls=cls, instance_id=1)
        method = SymbolicMethod(name="action")

        bound = BoundMethod(instance=instance, method=method)

        assert bound.instance == instance
        assert bound.method == method

    def test_call_bound_method(self):
        """Test calling a bound method."""
        cls = SymbolicClass(name="Counter")
        instance = SymbolicInstance(cls=cls, instance_id=1)
        instance.set_attr("count", 0)

        def increment(self):
            self.set_attr("count", self.get_attr("count") + 1)
            return self.get_attr("count")

        method = SymbolicMethod(name="increment", func=increment)
        bound = BoundMethod(instance=instance, method=method)

        result = bound()
        assert result == 1


class TestClassRegistry:
    """Tests for ClassRegistry."""

    def test_register_class(self):
        """Test registering a class."""
        registry = ClassRegistry()

        cls = SymbolicClass(name="MyClass", module="mymodule")
        registry.register_class(cls)

        found = registry.get_class("MyClass", "mymodule")
        assert found == cls

    def test_get_builtin(self):
        """Test getting builtin classes."""
        registry = ClassRegistry()

        int_cls = registry.get_builtin("int")
        str_cls = registry.get_builtin("str")

        assert int_cls is not None
        assert str_cls is not None

    def test_create_instance(self):
        """Test creating instance through registry."""
        registry = ClassRegistry()

        cls = SymbolicClass(name="Obj")
        registry.register_class(cls)

        instance = registry.create_instance(cls, {"x": 1})

        assert instance.cls == cls
        assert instance.get_attr("x") == 1

    def test_unique_instance_ids(self):
        """Test that instance IDs are unique."""
        registry = ClassRegistry()
        cls = SymbolicClass(name="Obj")

        i1 = registry.create_instance(cls)
        i2 = registry.create_instance(cls)
        i3 = registry.create_instance(cls)

        ids = {i1.instance_id, i2.instance_id, i3.instance_id}
        assert len(ids) == 3


class TestTypeChecker:
    """Tests for TypeChecker."""

    def test_isinstance_check_symbolic(self):
        """Test isinstance check for symbolic instance."""
        registry = ClassRegistry()
        checker = TypeChecker(registry)

        base = SymbolicClass(name="Base")
        derived = SymbolicClass(name="Derived", bases=[base])

        instance = SymbolicInstance(cls=derived, instance_id=1)

        result = checker.isinstance_check(instance, base)
        assert z3.is_true(result)

    def test_isinstance_check_python_value(self):
        """Test isinstance check for Python value."""
        registry = ClassRegistry()
        checker = TypeChecker(registry)

        int_cls = registry.get_builtin("int")

        result = checker.isinstance_check(42, int_cls)  # type: ignore[reportArgumentType]
        assert z3.is_true(result)

    def test_issubclass_check(self):
        """Test issubclass check."""
        registry = ClassRegistry()
        checker = TypeChecker(registry)

        base = SymbolicClass(name="Base")
        derived = SymbolicClass(name="Derived", bases=[base])

        result = checker.issubclass_check(derived, base)
        assert z3.is_true(result)

    def test_type_of(self):
        """Test getting type of value."""
        registry = ClassRegistry()
        checker = TypeChecker(registry)

        cls = SymbolicClass(name="Foo")
        instance = SymbolicInstance(cls=cls, instance_id=1)

        found_type = checker.type_of(instance)
        assert found_type == cls


class TestSymbolicProperty:
    """Tests for SymbolicProperty descriptor."""

    def test_property_get(self):
        """Test property getter."""
        cls = SymbolicClass(name="Obj")
        instance = SymbolicInstance(cls=cls, instance_id=1)
        instance.set_attr("_value", 42)

        prop = SymbolicProperty(
            fget=lambda self: self.get_attr("_value"),
        )

        result = prop.__get__(instance, cls)
        assert result == 42

    def test_property_set(self):
        """Test property setter."""
        cls = SymbolicClass(name="Obj")
        instance = SymbolicInstance(cls=cls, instance_id=1)

        prop = SymbolicProperty(
            fget=lambda self: self.get_attr("_value"),
            fset=lambda self, v: self.set_attr("_value", v),
        )

        prop.__set__(instance, 99)
        assert instance.get_attr("_value") == 99

    def test_property_readonly(self):
        """Test readonly property raises on set."""
        cls = SymbolicClass(name="Obj")
        instance = SymbolicInstance(cls=cls, instance_id=1)

        prop = SymbolicProperty(
            fget=lambda self: 42,
        )

        with pytest.raises(AttributeError):
            prop.__set__(instance, 1)
