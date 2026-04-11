
import z3

from pysymex.core.types.base import SYMBOLIC_NONE, SymbolicNoneType, TypeTag, fresh_name, reset_counters


class TestTypeTag:
    """Test suite for pysymex.core.types.base.TypeTag."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert TypeTag.INT.name == "INT"


def test_fresh_name() -> None:
    """Test fresh_name behavior."""
    reset_counters()
    assert fresh_name("x") == "x_0"


def test_reset_counters() -> None:
    """Test reset_counters behavior."""
    _ = fresh_name("y")
    reset_counters()
    assert fresh_name("y") == "y_0"


class TestSymbolicType:
    """Test suite for pysymex.core.types.base.SymbolicType."""

    def test_type_tag(self) -> None:
        """Test type_tag behavior."""
        assert SYMBOLIC_NONE.type_tag is TypeTag.NONE

    def test_name(self) -> None:
        """Test name behavior."""
        assert SYMBOLIC_NONE.name == "None"

    def test_to_z3(self) -> None:
        """Test to_z3 behavior."""
        assert z3.is_int_value(SYMBOLIC_NONE.to_z3())

    def test_is_truthy(self) -> None:
        """Test is_truthy behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_truthy())

    def test_is_falsy(self) -> None:
        """Test is_falsy behavior."""
        assert z3.is_true(SYMBOLIC_NONE.is_falsy())

    def test_symbolic_eq(self) -> None:
        """Test symbolic_eq behavior."""
        assert z3.is_true(SYMBOLIC_NONE.symbolic_eq(SymbolicNoneType()))

    def test_as_unified(self) -> None:
        """Test as_unified behavior."""
        assert z3.is_true(SYMBOLIC_NONE.as_unified().is_none)

    def test_is_int(self) -> None:
        """Test is_int behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_int)

    def test_is_bool(self) -> None:
        """Test is_bool behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_bool)

    def test_is_float(self) -> None:
        """Test is_float behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_float)

    def test_is_str(self) -> None:
        """Test is_str behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_str)

    def test_is_none(self) -> None:
        """Test is_none behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_none)

    def test_is_path(self) -> None:
        """Test is_path behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_path)

    def test_is_obj(self) -> None:
        """Test is_obj behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_obj)

    def test_is_list(self) -> None:
        """Test is_list behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_list)

    def test_is_dict(self) -> None:
        """Test is_dict behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_dict)


class TestSymbolicNoneType:
    """Test suite for pysymex.core.types.base.SymbolicNoneType."""

    def test_type_tag(self) -> None:
        """Test type_tag behavior."""
        assert SymbolicNoneType().type_tag is TypeTag.NONE

    def test_name(self) -> None:
        """Test name behavior."""
        assert SymbolicNoneType().name == "None"

    def test_to_z3(self) -> None:
        """Test to_z3 behavior."""
        assert z3.is_int_value(SymbolicNoneType().to_z3())

    def test_is_truthy(self) -> None:
        """Test is_truthy behavior."""
        assert z3.is_false(SymbolicNoneType().is_truthy())

    def test_is_falsy(self) -> None:
        """Test is_falsy behavior."""
        assert z3.is_true(SymbolicNoneType().is_falsy())

    def test_symbolic_eq(self) -> None:
        """Test symbolic_eq behavior."""
        assert z3.is_true(SymbolicNoneType().symbolic_eq(SymbolicNoneType()))

    def test_as_unified(self) -> None:
        """Test as_unified behavior."""
        assert z3.is_true(SymbolicNoneType().as_unified().is_none)

