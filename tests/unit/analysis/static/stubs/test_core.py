import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pysymex.analysis.static.stubs.builtins import BuiltinStubs
from pysymex.analysis.static.stubs.parser import StubParser
from pysymex.analysis.static.stubs.repository import StubRepository
from pysymex.analysis.static.stubs.resolver import StubBasedTypeResolver
from pysymex.analysis.static.types.engine.stubs import convert_stub_to_pytype
from pysymex.analysis.static.types.kinds import TypeKind
from pysymex.analysis.static.stubs.types import FunctionStub, StubType


def test_convert_stub_to_pytype_preserves_generic_parameters() -> None:
    pytype = convert_stub_to_pytype(StubType.list_of(StubType.int_type()))

    assert pytype.kind == TypeKind.LIST
    assert pytype.params[0].kind == TypeKind.INT


def test_convert_stub_to_pytype_preserves_union_members() -> None:
    pytype = convert_stub_to_pytype(StubType.union(StubType.int_type(), StubType.str_type()))

    assert pytype.kind == TypeKind.UNION
    assert {member.kind for member in pytype.union_members} == {TypeKind.INT, TypeKind.STR}


class TestStubParser:
    """Test suite for pysymex.analysis.static.stubs.parser.StubParser."""

    def test_parse_file(self) -> None:
        """Test parse_file behavior."""
        p = StubParser()
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".pyi", delete=False) as f:
            f.write("def foo() -> int: ...\n")
            name = f.name
        try:
            m = p.parse_file(name)
            assert "foo" in m.functions
        finally:
            os.remove(name)

    def test_parse_source(self) -> None:
        """Test parse_source behavior."""
        p = StubParser()
        source = (
            "def func(a: int) -> str: ...\n"
            "class MyClass:\n"
            "    attr: bool\n"
            "    def meth(self) -> bytes: ...\n"
            "my_var: float\n"
        )
        m = p.parse_source(source, "test_mod")
        assert "func" in m.functions
        assert "MyClass" in m.classes
        assert "my_var" in m.variables
        assert m.classes["MyClass"].attributes["attr"].name == "bool"
        assert m.classes["MyClass"].methods["meth"].return_type is not None
        assert m.classes["MyClass"].methods["meth"].return_type.name == "bytes"

        source2 = "x: int | str"
        m2 = p.parse_source(source2, "test_mod2")
        assert "x" in m2.variables
        assert m2.variables["x"].is_union

        source3 = "MyAlias = int"
        m3 = p.parse_source(source3, "test_mod3")
        assert "MyAlias" in m3.type_aliases


class TestStubRepository:
    """Test suite for pysymex.analysis.static.stubs.repository.StubRepository."""

    def test_add_search_path(self) -> None:
        """Test add_search_path behavior."""
        r = StubRepository()
        r.add_search_path(".")
        assert any(str(p) == "." for p in r.search_paths)

    def test_mypy_typeshed_search_path_does_not_import_mypy(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Find bundled mypy typeshed without executing optional-package code."""
        mypy_pkg = tmp_path / "mypy"
        typeshed = mypy_pkg / "typeshed"
        typeshed.mkdir(parents=True)
        (mypy_pkg / "__init__.py").write_text(
            "raise RuntimeError('mypy package should not be imported')\n",
            encoding="utf-8",
        )
        monkeypatch.delitem(sys.modules, "mypy", raising=False)
        monkeypatch.setattr(sys, "path", [str(tmp_path), *sys.path])

        repository = StubRepository()

        assert typeshed in repository.search_paths
        assert "mypy" not in sys.modules

    def test_get_stub(self) -> None:
        """Test get_stub behavior."""
        r = StubRepository()
        r.load_stub = MagicMock(return_value="mocked")
        assert r.get_stub("m") == "mocked"
        assert r.get_stub("m") == "mocked"

    def test_get_function_type(self) -> None:
        """Test get_function_type behavior."""
        r = StubRepository()
        m = MagicMock()
        m.functions = {"func": "func_stub"}
        r.get_stub = MagicMock(return_value=m)
        assert r.get_function_type("mod", "func") == "func_stub"
        assert r.get_function_type("mod", "func2") is None

    def test_get_class_type(self) -> None:
        """Test get_class_type behavior."""
        r = StubRepository()
        m = MagicMock()
        m.classes = {"cls": "cls_stub"}
        r.get_stub = MagicMock(return_value=m)
        assert r.get_class_type("mod", "cls") == "cls_stub"

    def test_get_method_type(self) -> None:
        """Test get_method_type behavior."""
        r = StubRepository()
        m = MagicMock()
        m.methods = {"meth": "meth_stub"}
        r.get_class_type = MagicMock(return_value=m)
        assert r.get_method_type("mod", "cls", "meth") == "meth_stub"


class TestStubBasedTypeResolver:
    """Test suite for pysymex.analysis.static.stubs.resolver.StubBasedTypeResolver."""

    def test_resolve_function_return(self) -> None:
        """Test resolve_function_return behavior."""
        repo = MagicMock()
        stub = FunctionStub("f")
        stub.return_type = StubType.int_type()
        repo.get_function_type.return_value = stub
        resolver = StubBasedTypeResolver(repo)
        assert resolver.resolve_function_return("m", "f") == StubType.int_type()

    def test_resolve_function_return_substitutes_typevar(self) -> None:
        repo = MagicMock()
        stub = FunctionStub(
            "identity",
            params={"value": StubType.typevar("T")},
            return_type=StubType.typevar("T"),
        )
        repo.get_function_type.return_value = stub
        resolver = StubBasedTypeResolver(repo)

        assert resolver.resolve_function_return("m", "identity", [StubType.str_type()]) == (
            StubType.str_type()
        )

    def test_resolve_function_return_substitutes_nested_typevar(self) -> None:
        repo = MagicMock()
        typevar = StubType.typevar("T")
        stub = FunctionStub(
            "to_list",
            params={"items": StubType("Iterable", "typing", (typevar,))},
            return_type=StubType.list_of(typevar),
        )
        repo.get_function_type.return_value = stub
        resolver = StubBasedTypeResolver(repo)

        assert resolver.resolve_function_return(
            "m",
            "to_list",
            [StubType.list_of(StubType.int_type())],
        ) == StubType.list_of(StubType.int_type())

    def test_resolve_function_return_conflicting_typevar_bindings_degrade_to_any(self) -> None:
        repo = MagicMock()
        typevar = StubType.typevar("T")
        stub = FunctionStub(
            "choose",
            params={"left": typevar, "right": typevar},
            return_type=typevar,
        )
        repo.get_function_type.return_value = stub
        resolver = StubBasedTypeResolver(repo)

        assert (
            resolver.resolve_function_return(
                "m",
                "choose",
                [StubType.int_type(), StubType.str_type()],
            )
            == StubType.any_type()
        )

    def test_resolve_method_return(self) -> None:
        """Test resolve_method_return behavior."""
        repo = MagicMock()
        stub = FunctionStub("m")
        stub.return_type = StubType.str_type()
        repo.get_method_type.return_value = stub
        resolver = StubBasedTypeResolver(repo)
        assert resolver.resolve_method_return("m", "c", "m") == StubType.str_type()

    def test_resolve_method_return_substitutes_typevar_after_bound_self(self) -> None:
        repo = MagicMock()
        typevar = StubType.typevar("T")
        stub = FunctionStub(
            "echo",
            params={"self": StubType("Box", "m"), "value": typevar},
            return_type=typevar,
        )
        repo.get_method_type.return_value = stub
        resolver = StubBasedTypeResolver(repo)

        assert resolver.resolve_method_return("m", "Box", "echo", [StubType.bytes_type()]) == (
            StubType.bytes_type()
        )

    def test_resolve_attribute(self) -> None:
        """Test resolve_attribute behavior."""
        repo = MagicMock()
        cls_stub = MagicMock()
        cls_stub.attributes = {"a": StubType.int_type()}
        cls_stub.class_vars = {}
        cls_stub.methods = {}
        repo.get_class_type.return_value = cls_stub
        resolver = StubBasedTypeResolver(repo)
        assert resolver.resolve_attribute("m", "c", "a") == StubType.int_type()

        cls_stub.attributes = {}
        cls_stub.class_vars = {"b": StubType.str_type()}
        assert resolver.resolve_attribute("m", "c", "b") == StubType.str_type()

    def test_check_assignable(self) -> None:
        """Test check_assignable behavior."""
        res = StubBasedTypeResolver()
        assert res.check_assignable(StubType.int_type(), StubType.any_type())
        assert res.check_assignable(StubType.int_type(), StubType.int_type())
        assert not res.check_assignable(StubType.int_type(), StubType.str_type())
        assert res.check_assignable(StubType.none_type(), StubType.optional(StubType.int_type()))
        assert res.check_assignable(
            StubType.list_of(StubType.int_type()), StubType.list_of(StubType.int_type())
        )
        assert res.check_assignable(
            StubType.int_type(), StubType.union(StubType.int_type(), StubType.str_type())
        )


class TestBuiltinStubs:
    """Test suite for pysymex.analysis.static.stubs.builtins.BuiltinStubs."""

    def test_get_builtin_module(self) -> None:
        """Test get_builtin_module behavior."""
        m = BuiltinStubs.get_builtin_module()
        assert "len" in m.functions
        assert "isinstance" in m.functions

    def test_get_collections_module(self) -> None:
        """Test get_collections_module behavior."""
        m = BuiltinStubs.get_collections_module()
        assert "defaultdict" in m.classes
        assert "deque" in m.classes
