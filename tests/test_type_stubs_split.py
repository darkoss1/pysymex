"""Tests for type stubs types and core parsing/resolution.

Targets the split modules:
  - pysymex.analysis.type_stubs_types
  - pysymex.analysis.type_stubs_core
  - pysymex.analysis.type_stubs (hub re-exports)

These modules had ZERO test coverage prior to this file.
"""

from __future__ import annotations


import pytest


from pysymex.analysis.type_stubs import (
    StubType,
    FunctionStub,
    ClassStub,
    ModuleStub,
    StubParser,
    StubRepository,
    StubBasedTypeResolver,
    BuiltinStubs,
)


class TestStubType:
    """Tests for the StubType frozen dataclass and its class methods."""

    def test_primitive_types(self):
        """All primitive factory methods should return distinct StubType instances."""

        primitives = {
            "int": StubType.int_type(),
            "str": StubType.str_type(),
            "float": StubType.float_type(),
            "bool": StubType.bool_type(),
            "bytes": StubType.bytes_type(),
            "None": StubType.none_type(),
            "Any": StubType.any_type(),
            "object": StubType.object_type(),
        }

        for name, stub in primitives.items():
            assert isinstance(stub, StubType)

            assert stub.name == name

    def test_list_of(self):
        t = StubType.list_of(StubType.int_type())

        assert t.name == "list"

        assert len(t.type_args) == 1

        assert t.type_args[0].name == "int"

    def test_dict_of(self):
        t = StubType.dict_of(StubType.str_type(), StubType.int_type())

        assert t.name == "dict"

        assert len(t.type_args) == 2

        assert t.type_args[0].name == "str"

        assert t.type_args[1].name == "int"

    def test_set_of(self):
        t = StubType.set_of(StubType.str_type())

        assert t.name == "set"

        assert len(t.type_args) == 1

    def test_tuple_of(self):
        t = StubType.tuple_of(StubType.int_type(), StubType.str_type())

        assert t.name == "tuple"

        assert len(t.type_args) == 2

    def test_optional(self):
        t = StubType.optional(StubType.int_type())

        assert t.is_optional

    def test_union(self):
        t = StubType.union(StubType.int_type(), StubType.str_type())

        assert t.is_union

        assert len(t.union_members) == 2

    def test_callable(self):
        t = StubType.callable(
            [StubType.int_type(), StubType.str_type()],
            StubType.bool_type(),
        )

        assert t.is_callable

        assert len(t.param_types) == 2

        assert t.return_type is not None

        assert t.return_type.name == "bool"

    def test_literal(self):
        t = StubType.literal(1, 2, 3)

        assert t.is_literal

        assert t.literal_values == (1, 2, 3)

    def test_typevar(self):
        t = StubType.typevar("T")

        assert t.is_typevar

        assert t.name == "T"

    def test_frozen_hashable(self):
        """StubType is frozen, so must be hashable."""

        t1 = StubType.int_type()

        t2 = StubType.int_type()

        assert t1 == t2

        assert hash(t1) == hash(t2)

        s = {t1, t2}

        assert len(s) == 1

    def test_str_representation(self):
        t = StubType.int_type()

        assert "int" in str(t)

    def test_to_pytype(self):
        """to_pytype() should return a PyType instance without errors."""

        t = StubType.int_type()

        result = t.to_pytype()

        assert result is not None


class TestFunctionStub:
    def test_basic_construction(self):
        f = FunctionStub(
            name="foo",
            params={"x": StubType.int_type()},
            return_type=StubType.str_type(),
        )

        assert f.name == "foo"

        assert "x" in f.params

        assert f.return_type.name == "str"

    def test_defaults(self):
        f = FunctionStub(name="bar")

        assert f.params == {}

        assert f.return_type is None

        assert not f.is_staticmethod

        assert not f.is_classmethod

        assert not f.is_property

        assert not f.is_abstractmethod

        assert not f.is_overload

    def test_overloads(self):
        overload1 = FunctionStub(name="baz", params={"x": StubType.int_type()})

        overload2 = FunctionStub(name="baz", params={"x": StubType.str_type()})

        f = FunctionStub(name="baz", overloads=[overload1, overload2])

        assert len(f.overloads) == 2


class TestClassStub:
    def test_basic_construction(self):
        method = FunctionStub(name="do_thing", return_type=StubType.none_type())

        c = ClassStub(
            name="MyClass",
            methods={"do_thing": method},
            attributes={"value": StubType.int_type()},
        )

        assert c.name == "MyClass"

        assert "do_thing" in c.methods

        assert "value" in c.attributes

    def test_defaults(self):
        c = ClassStub(name="Empty")

        assert c.bases == []

        assert c.methods == {}

        assert c.attributes == {}

        assert not c.is_protocol

        assert not c.is_abstract

    def test_protocol_class(self):
        c = ClassStub(name="MyProto", is_protocol=True)

        assert c.is_protocol


class TestModuleStub:
    def test_basic_construction(self):
        func = FunctionStub(name="helper")

        cls = ClassStub(name="Widget")

        m = ModuleStub(
            name="mymodule",
            functions={"helper": func},
            classes={"Widget": cls},
            variables={"VERSION": StubType.str_type()},
        )

        assert m.name == "mymodule"

        assert "helper" in m.functions

        assert "Widget" in m.classes

        assert "VERSION" in m.variables

    def test_defaults(self):
        m = ModuleStub(name="empty")

        assert m.functions == {}

        assert m.classes == {}

        assert m.variables == {}

        assert m.type_aliases == {}

        assert m.imports == {}

        assert m.submodules == {}


class TestStubParser:
    def test_parse_simple_function(self):
        source = "def foo(x: int) -> str: ..."

        parser = StubParser()

        module = parser.parse_source(source, "test_mod")

        assert isinstance(module, ModuleStub)

        assert "foo" in module.functions

        foo = module.functions["foo"]

        assert foo.name == "foo"

        assert "x" in foo.params

    def test_parse_class(self):
        source = "class Foo:\n" "    def bar(self) -> int: ...\n" "    x: str\n"

        parser = StubParser()

        module = parser.parse_source(source, "test_mod")

        assert "Foo" in module.classes

        cls = module.classes["Foo"]

        assert cls.name == "Foo"

        assert "bar" in cls.methods

    def test_parse_variable(self):
        source = "VERSION: str\nDEBUG: bool"

        parser = StubParser()

        module = parser.parse_source(source, "test_mod")

        assert "VERSION" in module.variables

        assert "DEBUG" in module.variables

    def test_parse_empty_source(self):
        parser = StubParser()

        module = parser.parse_source("", "empty")

        assert isinstance(module, ModuleStub)

        assert module.name == "empty"

    def test_parse_complex_types(self):
        source = "def process(items: list[int], mapping: dict[str, float]) -> None: ..."

        parser = StubParser()

        module = parser.parse_source(source, "complex_mod")

        assert "process" in module.functions


class TestBuiltinStubs:
    def test_builtin_module(self):
        m = BuiltinStubs.get_builtin_module()

        assert isinstance(m, ModuleStub)

        assert "len" in m.functions

        assert "range" in m.functions

        assert "isinstance" in m.functions

    def test_collections_module(self):
        m = BuiltinStubs.get_collections_module()

        assert isinstance(m, ModuleStub)

        assert "defaultdict" in m.classes or "defaultdict" in m.functions

        assert "Counter" in m.classes or "Counter" in m.functions

    def test_builtin_len_signature(self):
        m = BuiltinStubs.get_builtin_module()

        len_stub = m.functions["len"]

        assert len_stub.return_type is not None

        assert len_stub.return_type.name == "int"


class TestStubRepository:
    def test_construction(self):
        repo = StubRepository()

        assert repo is not None

    def test_get_stub_returns_module_or_none(self):
        repo = StubRepository()

        result = repo.get_stub("nonexistent_module_xyz_123")

        assert result is None or isinstance(result, ModuleStub)


class TestStubBasedTypeResolver:
    def test_construction_default(self):
        resolver = StubBasedTypeResolver()

        assert resolver is not None

    def test_check_assignable_same_type(self):
        resolver = StubBasedTypeResolver()

        assert resolver.check_assignable(StubType.int_type(), StubType.int_type())

    def test_check_assignable_any(self):
        resolver = StubBasedTypeResolver()

        assert resolver.check_assignable(StubType.any_type(), StubType.int_type())


class TestTypeStubsHub:
    def test_types_reexported(self):
        from pysymex.analysis.type_stubs import StubType, FunctionStub, ClassStub, ModuleStub

        assert StubType is not None

        assert FunctionStub is not None

        assert ClassStub is not None

        assert ModuleStub is not None

    def test_core_reexported(self):
        from pysymex.analysis.type_stubs import (
            StubParser,
            StubRepository,
            StubBasedTypeResolver,
            BuiltinStubs,
        )

        assert StubParser is not None

        assert StubRepository is not None

        assert StubBasedTypeResolver is not None

        assert BuiltinStubs is not None

    def test_identity_types(self):
        from pysymex.analysis.type_stubs.types import StubType as T1

        from pysymex.analysis.type_stubs import StubType as T2

        assert T1 is T2

    def test_identity_core(self):
        from pysymex.analysis.type_stubs.core import StubParser as C1

        from pysymex.analysis.type_stubs import StubParser as C2

        assert C1 is C2
