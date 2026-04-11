import pysymex.core.objects.oop as mod
import pysymex.core.types.scalars as scalars_mod

import itertools


if not hasattr(scalars_mod, "next_address"):
    _next_addr_counter = itertools.count(1)
    setattr(scalars_mod, "next_address", lambda: next(_next_addr_counter))


def _f(*args: object, **kwargs: object) -> None:
    return None


def _prop_getter(obj: mod.SymbolicObject) -> object:
    return 1


class TestMethodType:
    def test_initialization(self) -> None:
        assert mod.MethodType.INSTANCE.name == "INSTANCE"


class TestEnhancedMethod:
    def test_is_bound(self) -> None:
        m = mod.EnhancedMethod(func=_f)
        assert not m.is_bound

    def test_bind_to_instance(self) -> None:
        cls = mod.SymbolicClass("C")
        obj = mod.SymbolicObject(cls)
        m = mod.EnhancedMethod(func=_f)
        assert m.bind_to_instance(obj).is_bound

    def test_bind_to_class(self) -> None:
        cls = mod.SymbolicClass("C")
        m = mod.EnhancedMethod(func=_f, method_type=mod.MethodType.CLASS)
        assert m.bind_to_class(cls).bound_to is cls

    def test_get_call_args(self) -> None:
        cls = mod.SymbolicClass("C")
        obj = mod.SymbolicObject(cls)
        m = mod.EnhancedMethod(func=_f).bind_to_instance(obj)
        args, _ = m.get_call_args((1,), {})
        assert args[0] is obj


class TestInitParameter:
    def test_to_symbolic(self) -> None:
        p = mod.InitParameter(name="x", type_hint="int")
        assert p.to_symbolic(0) is not None


class TestEnhancedClass:
    def test_name(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        assert c.name == "A"

    def test_qualname(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A", qualname="pkg.A"))
        assert c.qualname == "pkg.A"

    def test_is_abstract(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"), abstract_methods={"m"})
        assert c.is_abstract

    def test_add_method(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        c.add_method("m", _f)
        assert c.get_method("m") is not None

    def test_add_property(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        c.add_property("p", fget=_prop_getter)
        assert "p" in c.properties

    def test_set_init_params(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        c.set_init_params([mod.InitParameter(name="self", is_self=True), mod.InitParameter(name="x")])
        assert c.required_init_args == 1

    def test_get_method(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        c.add_method("m", _f)
        assert c.get_method("m") is not None

    def test_lookup_method(self) -> None:
        base = mod.SymbolicClass("Base")
        c = mod.EnhancedClass(base=mod.SymbolicClass("Child", bases=(base,)))
        base.attributes["m"] = mod.SymbolicAttribute(
            name="m",
            value=mod.EnhancedMethod(func=_f, name="m"),
            is_method=True,
        )
        assert c.lookup_method("m") is not None


class TestEnhancedObject:
    def test_id(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        obj = mod.EnhancedObject(base=mod.SymbolicObject(c.base), enhanced_class=c)
        assert obj.id is not None

    def test_cls(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        obj = mod.EnhancedObject(base=mod.SymbolicObject(c.base), enhanced_class=c)
        assert obj.cls.name == "A"

    def test_get_attribute(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        obj = mod.EnhancedObject(base=mod.SymbolicObject(c.base), enhanced_class=c)
        obj.base.set_attribute("x", 4)
        value, found = obj.get_attribute("x")
        assert found and value == 4

    def test_set_attribute(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        obj = mod.EnhancedObject(base=mod.SymbolicObject(c.base), enhanced_class=c)
        assert obj.set_attribute("x", 3)

    def test_call_method(self) -> None:
        c = mod.EnhancedClass(base=mod.SymbolicClass("A"))
        c.add_method("m", _f)
        obj = mod.EnhancedObject(base=mod.SymbolicObject(c.base), enhanced_class=c)
        _, found = obj.call_method("m")
        assert found


class TestEnhancedClassRegistry:
    def test_register_class(self) -> None:
        reg = mod.EnhancedClassRegistry()
        cls = reg.register_class("X")
        assert cls.name == "X"

    def test_get_class(self) -> None:
        reg = mod.EnhancedClassRegistry()
        reg.register_class("X")
        assert reg.get_class("X") is not None

    def test_register_by_code(self) -> None:
        reg = mod.EnhancedClassRegistry()
        cls = reg.register_class("X")
        reg.register_by_code(1, cls)
        assert reg.get_by_code(1) is cls

    def test_get_by_code(self) -> None:
        reg = mod.EnhancedClassRegistry()
        cls = reg.register_class("X")
        reg.register_by_code(3, cls)
        assert reg.get_by_code(3) is cls

    def test_list_classes(self) -> None:
        reg = mod.EnhancedClassRegistry()
        reg.register_class("X")
        assert "X" in reg.list_classes()


def test_create_enhanced_instance() -> None:
    reg = mod.EnhancedClassRegistry()
    cls = reg.register_class("X")
    state = mod.ObjectState()
    obj, constraints = mod.create_enhanced_instance(cls, state)
    assert obj.initialized and constraints == []


def test_extract_init_params() -> None:
    def f(self: object, x: int, y: int = 1) -> None:
        return None

    params = mod.extract_init_params(f.__code__)
    assert [p.name for p in params[:2]] == ["self", "x"]


def test_is_dataclass() -> None:
    cls = mod.EnhancedClass(base=mod.SymbolicClass("X"))
    assert not mod.is_dataclass(cls)


def test_make_dataclass() -> None:
    cls = mod.EnhancedClass(base=mod.SymbolicClass("X"))
    dc = mod.make_dataclass(cls, {"x": ("int", 0)})
    assert dc.is_dataclass and dc.required_init_args == 0


class TestEnhancedSuper:
    def test_get_method(self) -> None:
        base = mod.SymbolicClass("Base")
        base.attributes["m"] = mod.SymbolicAttribute(
            name="m",
            value=mod.EnhancedMethod(func=_f),
            is_method=True,
        )
        child = mod.SymbolicClass("Child", bases=(base,))
        echild = mod.EnhancedClass(base=child)
        obj = mod.EnhancedObject(base=mod.SymbolicObject(child), enhanced_class=echild)
        sup = mod.EnhancedSuper(type_=echild, obj=obj)
        assert sup.get_method("m") is not None


def test_get_enhanced_class() -> None:
    mod.register_enhanced_class("GlobalCls")
    assert mod.get_enhanced_class("GlobalCls") is not None


def test_register_enhanced_class() -> None:
    registered = mod.register_enhanced_class("Registered")
    assert registered.name == "Registered"
