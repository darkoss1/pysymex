import tempfile
import os
from unittest.mock import MagicMock
from pysymex.analysis.type_stubs.core import (
    StubParser, StubRepository, StubBasedTypeResolver, BuiltinStubs
)
from pysymex.analysis.type_stubs.types import StubType, FunctionStub

class TestStubParser:
    """Test suite for pysymex.analysis.type_stubs.core.StubParser."""
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

        # Check union shorthand (BitOr)
        source2 = "x: int | str"
        m2 = p.parse_source(source2, "test_mod2")
        assert "x" in m2.variables
        assert m2.variables["x"].is_union

        # Check type alias
        source3 = "MyAlias = int"
        m3 = p.parse_source(source3, "test_mod3")
        assert "MyAlias" in m3.type_aliases


class TestStubRepository:
    """Test suite for pysymex.analysis.type_stubs.core.StubRepository."""
    def test_add_search_path(self) -> None:
        """Test add_search_path behavior."""
        r = StubRepository()
        r.add_search_path(".")
        assert any(str(p) == "." for p in r._search_paths)  # type: ignore[reportPrivateUsage]

    def test_get_stub(self) -> None:
        """Test get_stub behavior."""
        r = StubRepository()
        r._load_stub = MagicMock(return_value="mocked") # type: ignore[method-assign]
        assert r.get_stub("m") == "mocked"
        assert r.get_stub("m") == "mocked"

    def test_get_function_type(self) -> None:
        """Test get_function_type behavior."""
        r = StubRepository()
        m = MagicMock()
        m.functions = {"func": "func_stub"}
        r.get_stub = MagicMock(return_value=m) # type: ignore
        assert r.get_function_type("mod", "func") == "func_stub"
        assert r.get_function_type("mod", "func2") is None

    def test_get_class_type(self) -> None:
        """Test get_class_type behavior."""
        r = StubRepository()
        m = MagicMock()
        m.classes = {"cls": "cls_stub"}
        r.get_stub = MagicMock(return_value=m) # type: ignore
        assert r.get_class_type("mod", "cls") == "cls_stub"

    def test_get_method_type(self) -> None:
        """Test get_method_type behavior."""
        r = StubRepository()
        m = MagicMock()
        m.methods = {"meth": "meth_stub"}
        r.get_class_type = MagicMock(return_value=m) # type: ignore
        assert r.get_method_type("mod", "cls", "meth") == "meth_stub"

class TestStubBasedTypeResolver:
    """Test suite for pysymex.analysis.type_stubs.core.StubBasedTypeResolver."""
    def test_resolve_function_return(self) -> None:
        """Test resolve_function_return behavior."""
        repo = MagicMock()
        stub = FunctionStub("f")
        stub.return_type = StubType.int_type()
        repo.get_function_type.return_value = stub
        resolver = StubBasedTypeResolver(repo)
        assert resolver.resolve_function_return("m", "f") == StubType.int_type()

    def test_resolve_method_return(self) -> None:
        """Test resolve_method_return behavior."""
        repo = MagicMock()
        stub = FunctionStub("m")
        stub.return_type = StubType.str_type()
        repo.get_method_type.return_value = stub
        resolver = StubBasedTypeResolver(repo)
        assert resolver.resolve_method_return("m", "c", "m") == StubType.str_type()

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
        assert res.check_assignable(StubType.list_of(StubType.int_type()), StubType.list_of(StubType.int_type()))
        assert res.check_assignable(StubType.int_type(), StubType.union(StubType.int_type(), StubType.str_type()))

class TestBuiltinStubs:
    """Test suite for pysymex.analysis.type_stubs.core.BuiltinStubs."""
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
