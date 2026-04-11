import z3

import pysymex.core.objects.model as mod
from pysymex.core.objects.types import SymbolicAttribute


def test_get_builtin_class() -> None:
    cls = mod.get_builtin_class("int")
    assert cls is not None and cls.name == "int"


def test_get_class_for_value() -> None:
    assert mod.get_class_for_value(True).name == "bool"


class TestObjectState:
    def test_create_object(self) -> None:
        state = mod.ObjectState()
        cls = state.create_class("Thing")
        obj = state.create_object(cls)
        assert obj.cls is cls

    def test_create_class(self) -> None:
        state = mod.ObjectState()
        cls = state.create_class("A")
        assert state.get_class("A") is cls

    def test_get_object(self) -> None:
        state = mod.ObjectState()
        obj = state.create_object(mod.OBJECT_CLASS)
        assert state.get_object(obj.id) is obj

    def test_get_class(self) -> None:
        state = mod.ObjectState()
        assert state.get_class("str") is mod.STR_CLASS

    def test_isinstance_check(self) -> None:
        state = mod.ObjectState()
        obj = state.create_object(mod.INT_CLASS)
        assert z3.is_true(state.isinstance_check(obj, mod.OBJECT_CLASS))

    def test_identity_equal(self) -> None:
        state = mod.ObjectState()
        obj = state.create_object(mod.OBJECT_CLASS)
        assert z3.is_expr(state.identity_equal(obj, obj))

    def test_clone(self) -> None:
        state = mod.ObjectState()
        cloned = state.clone()
        assert cloned is not state and cloned.classes is state.classes


def test_getattr_symbolic() -> None:
    obj = mod.SymbolicObject(cls=mod.OBJECT_CLASS)
    obj.set_attribute("x", 7)
    value, found = mod.getattr_symbolic(obj, "x")
    assert found and value == 7


def test_setattr_symbolic() -> None:
    obj = mod.SymbolicObject(cls=mod.OBJECT_CLASS)
    assert mod.setattr_symbolic(obj, "x", 9)
    assert obj.get_attribute("x") is not None


def test_delattr_symbolic() -> None:
    obj = mod.SymbolicObject(cls=mod.OBJECT_CLASS)
    obj.set_attribute("x", 1)
    assert mod.delattr_symbolic(obj, "x")


def test_hasattr_symbolic() -> None:
    obj = mod.SymbolicObject(cls=mod.OBJECT_CLASS)
    obj.set_attribute("x", 1)
    assert z3.is_true(mod.hasattr_symbolic(obj, "x"))


def test_isinstance_symbolic() -> None:
    obj = mod.SymbolicObject(cls=mod.INT_CLASS)
    assert z3.is_true(mod.isinstance_symbolic(obj, mod.OBJECT_CLASS))


def test_issubclass_symbolic() -> None:
    assert z3.is_true(mod.issubclass_symbolic(mod.BOOL_CLASS, mod.INT_CLASS))


def test_type_of() -> None:
    obj = mod.SymbolicObject(cls=mod.STR_CLASS)
    assert mod.type_of(obj) is mod.STR_CLASS


def test_create_instance() -> None:
    state = mod.ObjectState()
    cls = state.create_class("Box")
    obj = mod.create_instance(cls, state, {"v": 3})
    assert obj.get_attribute("v") is not None


def test_call_method() -> None:
    obj = mod.SymbolicObject(cls=mod.OBJECT_CLASS)
    obj.attributes["m"] = SymbolicAttribute(name="m", value=lambda: 1, is_method=True)
    result, found = mod.call_method(obj, "m")
    assert found and result is None
