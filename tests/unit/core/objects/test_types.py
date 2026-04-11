import z3

import pysymex.core.objects.types as mod


class TestObjectId:
    def test_id(self) -> None:
        oid = mod.ObjectId("x")
        assert oid.id > 0

    def test_name(self) -> None:
        oid = mod.ObjectId("named")
        assert oid.name == "named"

    def test_to_z3(self) -> None:
        oid = mod.ObjectId("z")
        assert z3.is_expr(oid.to_z3())


class TestAttributeState:
    def test_initialization(self) -> None:
        assert mod.AttributeState.CONCRETE != mod.AttributeState.DELETED


class TestSymbolicAttribute:
    def test_concrete(self) -> None:
        attr = mod.SymbolicAttribute.concrete("a", 1)
        assert attr.is_present()

    def test_symbolic(self) -> None:
        attr = mod.SymbolicAttribute.symbolic("a", z3.Int("a"))
        assert attr.state == mod.AttributeState.SYMBOLIC

    def test_deleted(self) -> None:
        attr = mod.SymbolicAttribute.deleted("a")
        assert not attr.is_present()

    def test_unknown(self) -> None:
        attr = mod.SymbolicAttribute.unknown("a")
        assert attr.state == mod.AttributeState.UNKNOWN

    def test_is_present(self) -> None:
        assert mod.SymbolicAttribute.concrete("a", 1).is_present()


class TestSymbolicClass:
    def test_id(self) -> None:
        cls = mod.SymbolicClass("C")
        assert isinstance(cls.id, mod.ObjectId)

    def test_mro(self) -> None:
        cls = mod.SymbolicClass("C")
        assert cls.mro[0] is cls

    def test_get_attribute(self) -> None:
        cls = mod.SymbolicClass("C")
        cls.set_attribute("x", 1)
        assert cls.get_attribute("x") is not None

    def test_set_attribute(self) -> None:
        cls = mod.SymbolicClass("C")
        cls.set_attribute("k", 3)
        assert cls.has_attribute("k")

    def test_has_attribute(self) -> None:
        cls = mod.SymbolicClass("C")
        cls.set_attribute("a", 1)
        assert cls.has_attribute("a")

    def test_lookup_attribute(self) -> None:
        base = mod.SymbolicClass("Base")
        base.set_attribute("x", 1)
        child = mod.SymbolicClass("Child", bases=(base,))
        assert child.lookup_attribute("x") is not None

    def test_is_subclass_of(self) -> None:
        base = mod.SymbolicClass("Base")
        child = mod.SymbolicClass("Child", bases=(base,))
        assert child.is_subclass_of(base)


def test_compute_mro() -> None:
    base = mod.SymbolicClass("Base")
    child = mod.SymbolicClass("Child", bases=(base,))
    assert mod.compute_mro(child)[0] is child


class TestSymbolicObject:
    def test_id(self) -> None:
        obj = mod.SymbolicObject(mod.SymbolicClass("C"))
        assert isinstance(obj.id, mod.ObjectId)

    def test_get_attribute(self) -> None:
        obj = mod.SymbolicObject(mod.SymbolicClass("C"))
        obj.set_attribute("x", 10)
        assert obj.get_attribute("x") is not None

    def test_set_attribute(self) -> None:
        obj = mod.SymbolicObject(mod.SymbolicClass("C"))
        obj.set_attribute("x", 11)
        assert obj.has_attribute("x")

    def test_delete_attribute(self) -> None:
        obj = mod.SymbolicObject(mod.SymbolicClass("C"))
        obj.set_attribute("x", 11)
        assert obj.delete_attribute("x")

    def test_has_attribute(self) -> None:
        obj = mod.SymbolicObject(mod.SymbolicClass("C"))
        obj.set_attribute("x", 11)
        assert obj.has_attribute("x")

    def test_get_class(self) -> None:
        cls = mod.SymbolicClass("C")
        obj = mod.SymbolicObject(cls)
        assert obj.get_class() is cls

    def test_isinstance_of(self) -> None:
        base = mod.SymbolicClass("Base")
        child = mod.SymbolicClass("Child", bases=(base,))
        obj = mod.SymbolicObject(child)
        assert obj.isinstance_of(base)


class TestSymbolicMethod:
    def test_is_bound(self) -> None:
        method = mod.SymbolicMethod(func=lambda: None)
        assert not method.is_bound

    def test_bind(self) -> None:
        obj = mod.SymbolicObject(mod.SymbolicClass("C"))
        method = mod.SymbolicMethod(func=lambda: None)
        assert method.bind(obj).is_bound


class TestSymbolicProperty:
    def test_getter(self) -> None:
        prop = mod.SymbolicProperty(name="p").getter(lambda obj: 123)
        obj = mod.SymbolicObject(mod.SymbolicClass("C"))
        assert prop.__get__(obj) == 123

    def test_setter(self) -> None:
        box: dict[str, object] = {}
        prop = mod.SymbolicProperty(name="p").setter(lambda obj, v: box.update({"v": v}))
        obj = mod.SymbolicObject(mod.SymbolicClass("C"))
        prop.__set__(obj, 5)
        assert box["v"] == 5

    def test_deleter(self) -> None:
        box = {"deleted": False}
        prop = mod.SymbolicProperty(name="p").deleter(lambda obj: box.update({"deleted": True}))
        obj = mod.SymbolicObject(mod.SymbolicClass("C"))
        prop.__delete__(obj)
        assert box["deleted"] is True


class TestSymbolicSuper:
    def test_get_attribute(self) -> None:
        base = mod.SymbolicClass("Base")
        base.set_attribute("x", 77)
        child = mod.SymbolicClass("Child", bases=(base,))
        obj = mod.SymbolicObject(child)
        sup = mod.SymbolicSuper(type_=child, obj=obj)
        attr = sup.get_attribute("x")
        assert attr is not None and attr.value == 77
