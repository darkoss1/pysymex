"""
Tests for Phase 19: Object Model.

Tests symbolic object representation, class hierarchy,
method resolution order, attribute access, and class invariants.
"""

import pytest

import z3

from pysymex.core.object_model import (
    ObjectId,
    AttributeState,
    SymbolicAttribute,
    SymbolicClass,
    compute_mro,
    SymbolicObject,
    SymbolicMethod,
    SymbolicProperty,
    SymbolicSuper,
    OBJECT_CLASS,
    TYPE_CLASS,
    INT_CLASS,
    FLOAT_CLASS,
    BOOL_CLASS,
    STR_CLASS,
    LIST_CLASS,
    DICT_CLASS,
    BUILTIN_CLASSES,
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


from pysymex.analysis.invariants import (
    ClassInvariant,
    InvariantViolation,
    invariant,
    get_invariants,
    InvariantChecker,
    InvariantState,
    parse_invariant_condition,
    check_object_invariants,
)


class TestObjectId:
    """Tests for ObjectId class."""

    def test_unique_ids(self):
        """Each ObjectId is unique."""

        id1 = ObjectId("obj1")

        id2 = ObjectId("obj2")

        assert id1.id != id2.id

    def test_id_name(self):
        """ObjectId preserves name."""

        id1 = ObjectId("my_object")

        assert id1.name == "my_object"

    def test_id_equality(self):
        """ObjectId equality based on internal id."""

        id1 = ObjectId("obj")

        id2 = ObjectId("obj")

        assert id1 != id2

        assert id1 == id1

    def test_id_hash(self):
        """ObjectId is hashable."""

        id1 = ObjectId("obj1")

        id2 = ObjectId("obj2")

        d = {id1: "first", id2: "second"}

        assert d[id1] == "first"

    def test_id_to_z3(self):
        """ObjectId converts to Z3."""

        id1 = ObjectId("obj")

        z3_val = id1.to_z3()

        assert isinstance(z3_val, z3.ArithRef)


class TestSymbolicAttribute:
    """Tests for SymbolicAttribute class."""

    def test_concrete_attribute(self):
        """Create concrete attribute."""

        attr = SymbolicAttribute.concrete("x", 42)

        assert attr.name == "x"

        assert attr.value == 42

        assert attr.state == AttributeState.CONCRETE

        assert attr.is_present()

    def test_symbolic_attribute(self):
        """Create symbolic attribute."""

        val = z3.Int("x")

        attr = SymbolicAttribute.symbolic("x", val)

        assert attr.state == AttributeState.SYMBOLIC

        assert attr.is_present()

    def test_deleted_attribute(self):
        """Create deleted attribute."""

        attr = SymbolicAttribute.deleted("x")

        assert attr.state == AttributeState.DELETED

        assert not attr.is_present()

    def test_unknown_attribute(self):
        """Create unknown attribute."""

        attr = SymbolicAttribute.unknown("x")

        assert attr.state == AttributeState.UNKNOWN

        assert not attr.is_present()


class TestSymbolicClass:
    """Tests for SymbolicClass class."""

    def test_create_class(self):
        """Create a symbolic class."""

        cls = SymbolicClass(name="MyClass", bases=(OBJECT_CLASS,))

        assert cls.name == "MyClass"

        assert cls.qualname == "MyClass"

        assert OBJECT_CLASS in cls.bases

    def test_class_attribute(self):
        """Set and get class attribute."""

        cls = SymbolicClass(name="MyClass")

        cls.set_attribute("x", 10)

        attr = cls.get_attribute("x")

        assert attr is not None

        assert attr.value == 10

    def test_class_has_attribute(self):
        """Check if class has attribute."""

        cls = SymbolicClass(name="MyClass")

        cls.set_attribute("x", 10)

        assert cls.has_attribute("x")

        assert not cls.has_attribute("y")

    def test_mro_single_inheritance(self):
        """MRO for single inheritance."""

        parent = SymbolicClass(name="Parent", bases=(OBJECT_CLASS,))

        child = SymbolicClass(name="Child", bases=(parent,))

        mro = child.mro

        assert mro[0] == child

        assert mro[1] == parent

    def test_mro_diamond(self):
        """MRO for diamond inheritance."""

        a = SymbolicClass(name="A")

        b = SymbolicClass(name="B", bases=(a,))

        c = SymbolicClass(name="C", bases=(a,))

        d = SymbolicClass(name="D", bases=(b, c))

        mro = d.mro

        names = [cls.name for cls in mro]

        assert names.index("D") < names.index("B")

        assert names.index("B") < names.index("C")

        assert names.index("C") < names.index("A")

    def test_lookup_attribute_mro(self):
        """Lookup attribute through MRO."""

        parent = SymbolicClass(name="Parent")

        parent.set_attribute("x", 10)

        child = SymbolicClass(name="Child", bases=(parent,))

        attr = child.lookup_attribute("x")

        assert attr is not None

        assert attr.value == 10

    def test_is_subclass(self):
        """Check subclass relationship."""

        parent = SymbolicClass(name="Parent")

        child = SymbolicClass(name="Child", bases=(parent,))

        assert child.is_subclass_of(parent)

        assert child.is_subclass_of(child)

        assert not parent.is_subclass_of(child)


class TestSymbolicObject:
    """Tests for SymbolicObject class."""

    def test_create_object(self):
        """Create a symbolic object."""

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        assert obj.cls is cls

        assert obj.id is not None

    def test_object_attribute(self):
        """Set and get object attribute."""

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        obj.set_attribute("x", 42)

        attr = obj.get_attribute("x")

        assert attr is not None

        assert attr.value == 42

    def test_object_inherits_class_attr(self):
        """Object inherits class attribute."""

        cls = SymbolicClass(name="MyClass")

        cls.set_attribute("class_var", 100)

        obj = SymbolicObject(cls=cls)

        attr = obj.get_attribute("class_var")

        assert attr is not None

        assert attr.value == 100

    def test_instance_shadows_class(self):
        """Instance attribute shadows class attribute."""

        cls = SymbolicClass(name="MyClass")

        cls.set_attribute("x", 100)

        obj = SymbolicObject(cls=cls)

        obj.set_attribute("x", 42)

        attr = obj.get_attribute("x")

        assert attr.value == 42

    def test_delete_attribute(self):
        """Delete object attribute."""

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        obj.set_attribute("x", 42)

        result = obj.delete_attribute("x")

        assert result

        assert not obj.has_attribute("x", check_class=False)

    def test_isinstance_of(self):
        """Check isinstance relationship."""

        parent = SymbolicClass(name="Parent")

        child = SymbolicClass(name="Child", bases=(parent,))

        obj = SymbolicObject(cls=child)

        assert obj.isinstance_of(child)

        assert obj.isinstance_of(parent)


class TestSymbolicMethod:
    """Tests for SymbolicMethod class."""

    def test_unbound_method(self):
        """Create unbound method."""

        def func():
            pass

        method = SymbolicMethod(func=func)

        assert not method.is_bound

        assert method.__self__ is None

        assert method.__func__ is func

    def test_bound_method(self):
        """Create bound method."""

        def func():
            pass

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        method = SymbolicMethod(func=func).bind(obj)

        assert method.is_bound

        assert method.__self__ is obj

    def test_bind_to_instance(self):
        """Bind method to instance."""

        def func():
            pass

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        unbound = SymbolicMethod(func=func, owner=cls)

        bound = unbound.bind(obj)

        assert bound.is_bound

        assert bound.__self__ is obj


class TestSymbolicProperty:
    """Tests for SymbolicProperty class."""

    def test_property_getter(self):
        """Property with getter."""

        def fget(self):
            return 42

        prop = SymbolicProperty(fget=fget, name="x")

        assert prop.fget is fget

        assert prop.fset is None

    def test_property_setter(self):
        """Property with setter."""

        def fget(self):
            return 42

        def fset(self, val):
            pass

        prop = SymbolicProperty(fget=fget, name="x")

        prop_with_setter = prop.setter(fset)

        assert prop_with_setter.fget is fget

        assert prop_with_setter.fset is fset

    def test_property_deleter(self):
        """Property with deleter."""

        def fget(self):
            return 42

        def fdel(self):
            pass

        prop = SymbolicProperty(fget=fget, name="x")

        prop_with_deleter = prop.deleter(fdel)

        assert prop_with_deleter.fdel is fdel


class TestSymbolicSuper:
    """Tests for SymbolicSuper class."""

    def test_super_lookup(self):
        """Super lookup in parent class."""

        parent = SymbolicClass(name="Parent")

        parent.set_attribute("x", 100)

        child = SymbolicClass(name="Child", bases=(parent,))

        child.set_attribute("x", 42)

        obj = SymbolicObject(cls=child)

        sup = SymbolicSuper(type_=child, obj=obj)

        attr = sup.get_attribute("x")

        assert attr is not None

        assert attr.value == 100


class TestBuiltinClasses:
    """Tests for built-in class hierarchy."""

    def test_object_is_root(self):
        """object is the root class."""

        assert OBJECT_CLASS.name == "object"

        assert len(OBJECT_CLASS.bases) == 0

    def test_type_inherits_object(self):
        """type inherits from object."""

        assert OBJECT_CLASS in TYPE_CLASS.bases

    def test_int_inherits_object(self):
        """int inherits from object."""

        assert INT_CLASS.is_subclass_of(OBJECT_CLASS)

    def test_bool_inherits_int(self):
        """bool inherits from int."""

        assert BOOL_CLASS.is_subclass_of(INT_CLASS)

        assert BOOL_CLASS.is_subclass_of(OBJECT_CLASS)

    def test_get_builtin_class(self):
        """Get built-in class by name."""

        assert get_builtin_class("int") is INT_CLASS

        assert get_builtin_class("str") is STR_CLASS

        assert get_builtin_class("unknown") is None

    def test_get_class_for_value(self):
        """Get class for Python value."""

        assert get_class_for_value(42) is INT_CLASS

        assert get_class_for_value(3.14) is FLOAT_CLASS

        assert get_class_for_value(True) is BOOL_CLASS

        assert get_class_for_value("hello") is STR_CLASS

        assert get_class_for_value([1, 2]) is LIST_CLASS

        assert get_class_for_value(None) is not None


class TestObjectState:
    """Tests for ObjectState class."""

    def test_create_object(self):
        """Create object through state."""

        state = ObjectState()

        cls = state.create_class("MyClass")

        obj = state.create_object(cls)

        assert obj.cls is cls

        assert state.get_object(obj.id) is obj

    def test_create_class(self):
        """Create class through state."""

        state = ObjectState()

        cls = state.create_class("MyClass", bases=(OBJECT_CLASS,))

        assert cls.name == "MyClass"

        assert state.get_class("MyClass") is cls

    def test_builtin_classes_registered(self):
        """Built-in classes are registered."""

        state = ObjectState()

        assert state.get_class("int") is INT_CLASS

        assert state.get_class("object") is OBJECT_CLASS

    def test_isinstance_check(self):
        """Generate isinstance constraint."""

        state = ObjectState()

        cls = state.create_class("MyClass")

        obj = state.create_object(cls)

        result = state.isinstance_check(obj, cls)

        assert z3.is_true(result)

    def test_identity_equal(self):
        """Generate identity equality constraint."""

        state = ObjectState()

        cls = state.create_class("MyClass")

        obj1 = state.create_object(cls)

        obj2 = state.create_object(cls)

        same = state.identity_equal(obj1, obj1)

        diff = state.identity_equal(obj1, obj2)

        solver = z3.Solver()

        solver.add(same)

        assert solver.check() == z3.sat

    def test_clone_state(self):
        """Clone object state."""

        state = ObjectState()

        cls = state.create_class("MyClass")

        obj = state.create_object(cls)

        cloned = state.clone()

        assert cloned.get_class("MyClass") is cls

        cloned.create_class("OtherClass")

        assert state.get_class("OtherClass") is None


class TestAttributeProtocol:
    """Tests for attribute access protocol."""

    def test_getattr_instance(self):
        """Get instance attribute."""

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        obj.set_attribute("x", 42)

        value, found = getattr_symbolic(obj, "x")

        assert found

        assert value == 42

    def test_getattr_with_default(self):
        """Get attribute with default."""

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        value, found = getattr_symbolic(obj, "missing", default=99)

        assert found

        assert value == 99

    def test_setattr_instance(self):
        """Set instance attribute."""

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        result = setattr_symbolic(obj, "x", 42)

        assert result

        assert obj.has_attribute("x")

    def test_delattr_instance(self):
        """Delete instance attribute."""

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        obj.set_attribute("x", 42)

        result = delattr_symbolic(obj, "x")

        assert result

        assert not obj.has_attribute("x", check_class=False)

    def test_hasattr_symbolic(self):
        """Check attribute exists symbolically."""

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        obj.set_attribute("x", 42)

        has_x = hasattr_symbolic(obj, "x")

        has_y = hasattr_symbolic(obj, "y")

        assert z3.is_true(has_x)

        assert z3.is_false(has_y)


class TestTypeChecking:
    """Tests for type checking functions."""

    def test_isinstance_single(self):
        """isinstance with single class."""

        cls = SymbolicClass(name="MyClass", bases=(OBJECT_CLASS,))

        obj = SymbolicObject(cls=cls)

        result = isinstance_symbolic(obj, cls)

        assert z3.is_true(result)

    def test_isinstance_parent(self):
        """isinstance with parent class."""

        parent = SymbolicClass(name="Parent")

        child = SymbolicClass(name="Child", bases=(parent,))

        obj = SymbolicObject(cls=child)

        result = isinstance_symbolic(obj, parent)

        assert z3.is_true(result)

    def test_isinstance_tuple(self):
        """isinstance with tuple of classes."""

        cls1 = SymbolicClass(name="Class1")

        cls2 = SymbolicClass(name="Class2")

        obj = SymbolicObject(cls=cls1)

        result = isinstance_symbolic(obj, (cls1, cls2))

        assert z3.is_true(result)

    def test_issubclass_direct(self):
        """issubclass for direct subclass."""

        parent = SymbolicClass(name="Parent")

        child = SymbolicClass(name="Child", bases=(parent,))

        result = issubclass_symbolic(child, parent)

        assert z3.is_true(result)

    def test_type_of(self):
        """Get type of object."""

        cls = SymbolicClass(name="MyClass")

        obj = SymbolicObject(cls=cls)

        result = type_of(obj)

        assert result is cls


class TestObjectCreation:
    """Tests for object creation."""

    def test_create_instance_simple(self):
        """Create instance of class."""

        state = ObjectState()

        cls = state.create_class("MyClass")

        obj = create_instance(cls, state)

        assert obj.cls is cls

        assert state.get_object(obj.id) is obj

    def test_create_instance_with_attrs(self):
        """Create instance with initial attributes."""

        state = ObjectState()

        cls = state.create_class("MyClass")

        obj = create_instance(cls, state, init_attrs={"x": 10, "y": 20})

        assert obj.has_attribute("x")

        assert obj.has_attribute("y")


class TestClassInvariant:
    """Tests for ClassInvariant class."""

    def test_create_invariant(self):
        """Create class invariant."""

        inv = ClassInvariant(
            condition="self.balance >= 0",
            message="Balance must be non-negative",
            class_name="BankAccount",
        )

        assert inv.condition == "self.balance >= 0"

        assert "non-negative" in inv.message

    def test_invariant_str(self):
        """String representation."""

        inv = ClassInvariant(
            condition="self.x > 0",
            message="x must be positive",
        )

        s = str(inv)

        assert "self.x > 0" in s

        assert "positive" in s


class TestInvariantDecorator:
    """Tests for @invariant decorator."""

    def test_invariant_decorator(self):
        """Apply @invariant decorator."""

        @invariant("self.x >= 0", "x must be non-negative")
        class MyClass:
            def __init__(self):
                self.x = 0

        assert hasattr(MyClass, "__invariants__")

        assert len(MyClass.__invariants__) == 1

        assert MyClass.__invariants__[0].condition == "self.x >= 0"

    def test_multiple_invariants(self):
        """Multiple @invariant decorators."""

        @invariant("self.x >= 0")
        @invariant("self.y >= 0")
        class MyClass:
            pass

        assert len(MyClass.__invariants__) == 2

    def test_get_invariants_inheritance(self):
        """Get invariants with inheritance."""

        @invariant("self.x >= 0")
        class Parent:
            pass

        @invariant("self.y >= 0")
        class Child(Parent):
            pass

        invariants = get_invariants(Child)

        conditions = [inv.condition for inv in invariants]

        assert "self.x >= 0" in conditions

        assert "self.y >= 0" in conditions


class TestInvariantChecker:
    """Tests for InvariantChecker class."""

    def test_checker_holds(self):
        """Invariant holds."""

        checker = InvariantChecker()

        inv = ClassInvariant(condition="self.x >= 0", class_name="Test")

        x = z3.Int("self.x")

        cond = x >= 0

        checker.solver.add(x == 5)

        result = checker.check_invariant(inv, cond, "init", "__init__")

        assert result

        assert len(checker.violations) == 0

    def test_checker_violation(self):
        """Invariant violated."""

        checker = InvariantChecker()

        inv = ClassInvariant(condition="self.x >= 0", class_name="Test")

        x = z3.Int("self.x")

        cond = x >= 0

        result = checker.check_invariant(inv, cond, "init", "__init__")

        assert not result

        assert len(checker.violations) == 1

    def test_checker_with_constraints(self):
        """Check with path constraints."""

        checker = InvariantChecker()

        inv = ClassInvariant(condition="self.x >= 0", class_name="Test")

        x = z3.Int("self.x")

        cond = x >= 0

        path = [x >= 10]

        result = checker.check_invariant(inv, cond, "entry", "method", path)

        assert result


class TestInvariantState:
    """Tests for InvariantState class."""

    def test_register_class(self):
        """Register class invariants."""

        state = InvariantState()

        invs = [ClassInvariant(condition="self.x >= 0", class_name="Test")]

        state.register_class("Test", invs)

        assert state.get_invariants("Test") == invs

    def test_record_violation(self):
        """Record invariant violation."""

        state = InvariantState()

        inv = ClassInvariant(condition="self.x >= 0", class_name="Test")

        violation = InvariantViolation(
            invariant=inv,
            when="init",
            method_name="__init__",
        )

        state.record_violation(violation)

        assert state.has_violations()

        assert len(state.violations) == 1

    def test_get_violations_for_class(self):
        """Get violations for specific class."""

        state = InvariantState()

        inv1 = ClassInvariant(condition="self.x >= 0", class_name="ClassA")

        inv2 = ClassInvariant(condition="self.y >= 0", class_name="ClassB")

        state.record_violation(InvariantViolation(inv1, "init", "__init__"))

        state.record_violation(InvariantViolation(inv2, "init", "__init__"))

        violations_a = state.get_violations_for_class("ClassA")

        assert len(violations_a) == 1

        assert violations_a[0].invariant.class_name == "ClassA"


class TestInvariantParsing:
    """Tests for invariant condition parsing."""

    def test_parse_greater_equal(self):
        """Parse >= comparison."""

        self_attrs = {}

        cond = parse_invariant_condition("self.x >= 0", self_attrs)

        assert "self.x" in self_attrs

        solver = z3.Solver()

        solver.add(self_attrs["self.x"] == 5)

        solver.add(cond)

        assert solver.check() == z3.sat

    def test_parse_less_than(self):
        """Parse < comparison."""

        self_attrs = {}

        cond = parse_invariant_condition("self.x < 100", self_attrs)

        solver = z3.Solver()

        solver.add(self_attrs["self.x"] == 50)

        solver.add(cond)

        assert solver.check() == z3.sat

    def test_parse_two_attrs(self):
        """Parse comparison of two attributes."""

        self_attrs = {}

        cond = parse_invariant_condition("self.balance > self.min_balance", self_attrs)

        assert "self.balance" in self_attrs

        assert "self.min_balance" in self_attrs


class TestObjectModelIntegration:
    """Integration tests for object model."""

    def test_class_hierarchy(self):
        """Test class hierarchy with methods."""

        state = ObjectState()

        animal = state.create_class("Animal")

        animal.set_attribute("speak", lambda self: "...")

        dog = state.create_class("Dog", bases=(animal,))

        dog.set_attribute("speak", lambda self: "Woof!")

        fido = state.create_object(dog)

        assert fido.isinstance_of(dog)

        assert fido.isinstance_of(animal)

        speak_attr = fido.get_attribute("speak")

        assert speak_attr is not None

    def test_diamond_inheritance(self):
        """Test diamond inheritance pattern."""

        state = ObjectState()

        a = state.create_class("A")

        a.set_attribute("value", "A")

        b = state.create_class("B", bases=(a,))

        b.set_attribute("value", "B")

        c = state.create_class("C", bases=(a,))

        c.set_attribute("value", "C")

        d = state.create_class("D", bases=(b, c))

        obj = state.create_object(d)

        attr = obj.get_attribute("value")

        assert attr.value == "B"

    def test_invariant_checking(self):
        """Test full invariant checking flow."""

        @invariant("self.balance >= 0", "Balance cannot be negative")
        class BankAccount:
            def __init__(self, initial):
                self.balance = initial

        inv_state = InvariantState()

        invs = get_invariants(BankAccount)

        inv_state.register_class("BankAccount", invs)

        self_attrs = {"self.balance": z3.IntVal(100)}

        z3_cond = parse_invariant_condition("self.balance >= 0", self_attrs)

        checker = inv_state.checker

        result = checker.check_invariant(invs[0], z3_cond, "init", "__init__")

        assert result

    def test_method_binding_and_call(self):
        """Test method binding and calling."""

        state = ObjectState()

        cls = state.create_class("Calculator")

        def add(self, x, y):
            return x + y

        cls.set_attribute("add", add)

        cls.attributes["add"].is_method = True

        calc = state.create_object(cls)

        method, found = getattr_symbolic(calc, "add")

        assert found

        assert isinstance(method, SymbolicMethod)

        assert method.is_bound

        assert method.__self__ is calc
