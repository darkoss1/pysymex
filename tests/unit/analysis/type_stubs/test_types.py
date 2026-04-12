from pysymex.analysis.type_stubs.types import (
    StubType, FunctionStub, ClassStub, ModuleStub
)
from pysymex.analysis.type_inference import TypeKind

class TestStubType:
    """Test suite for pysymex.analysis.type_stubs.types.StubType."""
    def test_any_type(self) -> None:
        """Test any_type behavior."""
        assert StubType.any_type().name == "Any"

    def test_none_type(self) -> None:
        """Test none_type behavior."""
        assert StubType.none_type().name == "None"

    def test_int_type(self) -> None:
        """Test int_type behavior."""
        assert StubType.int_type().name == "int"

    def test_str_type(self) -> None:
        """Test str_type behavior."""
        assert StubType.str_type().name == "str"

    def test_bool_type(self) -> None:
        """Test bool_type behavior."""
        assert StubType.bool_type().name == "bool"

    def test_float_type(self) -> None:
        """Test float_type behavior."""
        assert StubType.float_type().name == "float"

    def test_bytes_type(self) -> None:
        """Test bytes_type behavior."""
        assert StubType.bytes_type().name == "bytes"

    def test_object_type(self) -> None:
        """Test object_type behavior."""
        assert StubType.object_type().name == "object"

    def test_list_of(self) -> None:
        """Test list_of behavior."""
        t = StubType.list_of(StubType.int_type())
        assert t.name == "list"
        assert len(t.type_args) == 1

    def test_dict_of(self) -> None:
        """Test dict_of behavior."""
        t = StubType.dict_of(StubType.str_type(), StubType.int_type())
        assert t.name == "dict"
        assert len(t.type_args) == 2

    def test_set_of(self) -> None:
        """Test set_of behavior."""
        t = StubType.set_of(StubType.int_type())
        assert t.name == "set"
        assert len(t.type_args) == 1

    def test_tuple_of(self) -> None:
        """Test tuple_of behavior."""
        t = StubType.tuple_of(StubType.int_type(), StubType.str_type())
        assert t.name == "tuple"
        assert len(t.type_args) == 2

    def test_optional(self) -> None:
        """Test optional behavior."""
        t = StubType.optional(StubType.int_type())
        assert t.is_optional

    def test_union(self) -> None:
        """Test union behavior."""
        t = StubType.union(StubType.int_type(), StubType.str_type())
        assert t.is_union
        assert len(t.union_members) == 2
        assert " | " in str(t)

    def test_callable(self) -> None:
        """Test callable behavior."""
        t = StubType.callable([StubType.int_type()], StubType.str_type())
        assert t.is_callable
        assert "Callable" in str(t)

    def test_literal(self) -> None:
        """Test literal behavior."""
        t = StubType.literal(1, 2)
        assert t.is_literal
        assert "Literal" in str(t)

    def test_typevar(self) -> None:
        """Test typevar behavior."""
        t = StubType.typevar("T")
        assert t.is_typevar

    def test_to_pytype(self) -> None:
        """Test to_pytype behavior."""
        pt = StubType.int_type().to_pytype()
        assert pt.kind == TypeKind.INT
        
        pt_opt = StubType.optional(StubType.int_type()).to_pytype()
        assert pt_opt.kind == TypeKind.OPTIONAL

        pt_union = StubType.union(StubType.int_type(), StubType.str_type()).to_pytype()
        assert pt_union.kind == TypeKind.UNION

class TestFunctionStub:
    """Test suite for pysymex.analysis.type_stubs.types.FunctionStub."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        f = FunctionStub("f")
        assert f.name == "f"

class TestClassStub:
    """Test suite for pysymex.analysis.type_stubs.types.ClassStub."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        c = ClassStub("C")
        assert c.name == "C"

class TestModuleStub:
    """Test suite for pysymex.analysis.type_stubs.types.ModuleStub."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        m = ModuleStub("m")
        assert m.name == "m"
