from pysymex.analysis.type_constraints.types import (
    TypeKind,
    Variance,
    SymbolicType,
    TypeIssueKind,
    TypeIssue,
)


class TestTypeKind:
    """Test suite for pysymex.analysis.type_constraints.types.TypeKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert TypeKind.INT.name == "INT"


class TestVariance:
    """Test suite for pysymex.analysis.type_constraints.types.Variance."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert Variance.INVARIANT.name == "INVARIANT"


class TestSymbolicType:
    """Test suite for pysymex.analysis.type_constraints.types.SymbolicType."""

    def test_int_type(self) -> None:
        """Test int_type behavior."""
        assert SymbolicType.int_type().kind == TypeKind.INT

    def test_float_type(self) -> None:
        """Test float_type behavior."""
        assert SymbolicType.float_type().kind == TypeKind.FLOAT

    def test_bool_type(self) -> None:
        """Test bool_type behavior."""
        assert SymbolicType.bool_type().kind == TypeKind.BOOL

    def test_str_type(self) -> None:
        """Test str_type behavior."""
        assert SymbolicType.str_type().kind == TypeKind.STR

    def test_none_type(self) -> None:
        """Test none_type behavior."""
        assert SymbolicType.none_type().kind == TypeKind.NONE

    def test_any_type(self) -> None:
        """Test any_type behavior."""
        assert SymbolicType.any_type().kind == TypeKind.ANY

    def test_never_type(self) -> None:
        """Test never_type behavior."""
        assert SymbolicType.never_type().kind == TypeKind.NEVER

    def test_list_of(self) -> None:
        """Test list_of behavior."""
        t = SymbolicType.list_of(SymbolicType.int_type())
        assert t.kind == TypeKind.LIST
        assert "list[int]" in str(t)

    def test_dict_of(self) -> None:
        """Test dict_of behavior."""
        t = SymbolicType.dict_of(SymbolicType.str_type(), SymbolicType.int_type())
        assert t.kind == TypeKind.DICT
        assert "dict[str, int]" in str(t)

    def test_tuple_of(self) -> None:
        """Test tuple_of behavior."""
        t = SymbolicType.tuple_of(SymbolicType.int_type(), SymbolicType.float_type())
        assert t.kind == TypeKind.TUPLE
        assert "tuple[int, float]" in str(t)

    def test_union_of(self) -> None:
        """Test union_of behavior."""
        t_int = SymbolicType.int_type()
        t_float = SymbolicType.float_type()
        t_never = SymbolicType.never_type()

        t1 = SymbolicType.union_of()
        assert t1.kind == TypeKind.NEVER

        t2 = SymbolicType.union_of(t_int, t_never)
        assert t2.kind == TypeKind.INT

        t3 = SymbolicType.union_of(t_int, t_float)
        assert t3.kind == TypeKind.UNION
        assert " | " in str(t3)

    def test_optional_of(self) -> None:
        """Test optional_of behavior."""
        t = SymbolicType.optional_of(SymbolicType.int_type())
        assert t.kind == TypeKind.UNION
        assert any(arg.kind == TypeKind.NONE for arg in t.args)

    def test_callable_type(self) -> None:
        """Test callable_type behavior."""
        t = SymbolicType.callable_type([SymbolicType.int_type()], SymbolicType.str_type())
        assert t.kind == TypeKind.CALLABLE
        assert "Callable" in str(t)

    def test_type_var(self) -> None:
        """Test type_var behavior."""
        t = SymbolicType.type_var("T", SymbolicType.int_type(), variance=Variance.COVARIANT)
        assert t.kind == TypeKind.TYPE_VAR
        assert t.name == "T"

    def test_literal(self) -> None:
        """Test literal behavior."""
        t = SymbolicType.literal(1, 2)
        assert t.kind == TypeKind.LITERAL
        assert "Literal" in str(t)

    def test_class_type(self) -> None:
        """Test class_type behavior."""
        t = SymbolicType.class_type("MyClass")
        assert t.kind == TypeKind.CLASS
        assert t.name == "MyClass"


class TestTypeIssueKind:
    """Test suite for pysymex.analysis.type_constraints.types.TypeIssueKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert TypeIssueKind.INCOMPATIBLE_TYPES.name == "INCOMPATIBLE_TYPES"


class TestTypeIssue:
    """Test suite for pysymex.analysis.type_constraints.types.TypeIssue."""

    def test_format(self) -> None:
        """Test format behavior."""
        issue = TypeIssue(
            kind=TypeIssueKind.INCOMPATIBLE_TYPES,
            message="Error msg",
            expected_type=SymbolicType.int_type(),
            actual_type=SymbolicType.str_type(),
            line_number=10,
        )
        fmt = issue.format()
        assert "INCOMPATIBLE_TYPES" in fmt
        assert "line 10" in fmt
        assert "expected int" in fmt
