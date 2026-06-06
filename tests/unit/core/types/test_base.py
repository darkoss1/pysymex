import re

import z3

from pysymex.core.types.base import (
    SYMBOLIC_NONE,
    SymbolicNoneType,
    TypeTag,
    fresh_name,
)

_FRESH_NAME_RE = re.compile(r"^(.+)_(\d+)$")


class TestTypeTag:
    """Test suite for pysymex.core.types.base.TypeTag."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert TypeTag.INT.name == "INT"


def test_fresh_name_prefix() -> None:
    """fresh_name returns 'prefix_<integer>' with the requested prefix."""
    result = fresh_name("x")
    match = _FRESH_NAME_RE.match(result)
    assert match is not None, f"fresh_name did not match expected pattern: {result}"
    assert match.group(1) == "x"
    assert int(match.group(2)) >= 0


def test_fresh_name_monotonic() -> None:
    """Successive fresh_name calls produce strictly increasing counters."""
    a = fresh_name("v")
    b = fresh_name("v")
    a_id = int(_FRESH_NAME_RE.match(a).group(2))  # type: ignore[union-attr]  # pattern guaranteed to match
    b_id = int(_FRESH_NAME_RE.match(b).group(2))  # type: ignore[union-attr]  # pattern guaranteed to match
    assert b_id > a_id, f"Counter did not increment: {a} -> {b}"


class TestSymbolicType:
    """Test suite for pysymex.core.types.base.SymbolicType."""

    def test_type_tag(self) -> None:
        """Test type_tag behavior."""
        assert SYMBOLIC_NONE.type_tag == "NoneType"

    def test_name(self) -> None:
        """Test name behavior."""
        assert SYMBOLIC_NONE.name == "None"

    def test_to_z3(self) -> None:
        """Test to_z3 behavior."""
        assert z3.is_false(SYMBOLIC_NONE.to_z3())

    def test_is_truthy(self) -> None:
        """Test is_truthy behavior."""
        assert z3.is_false(SYMBOLIC_NONE.is_truthy())

    def test_is_falsy(self) -> None:
        """Test is_falsy behavior."""
        assert z3.is_true(SYMBOLIC_NONE.is_falsy())

    def test_could_be_truthy(self) -> None:
        """Execution truthiness query matches the concrete none truthiness."""
        assert z3.eq(SYMBOLIC_NONE.could_be_truthy(), SYMBOLIC_NONE.is_truthy())

    def test_could_be_falsy(self) -> None:
        """Execution falsiness query matches the concrete none falsiness."""
        assert z3.eq(SYMBOLIC_NONE.could_be_falsy(), SYMBOLIC_NONE.is_falsy())

    def test_hash_value(self) -> None:
        """SymbolicType exposes content hashing for VMState deduplication."""
        assert SYMBOLIC_NONE.hash_value() == SymbolicNoneType().hash_value()

    def test_symbolic_eq(self) -> None:
        """Test symbolic_eq behavior."""
        assert z3.is_true(SYMBOLIC_NONE.symbolic_eq(SymbolicNoneType()))

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
        assert z3.is_true(SYMBOLIC_NONE.is_none)

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
        assert SymbolicNoneType().type_tag == "NoneType"

    def test_name(self) -> None:
        """Test name behavior."""
        assert SymbolicNoneType().name == "None"

    def test_to_z3(self) -> None:
        """Test to_z3 behavior."""
        assert z3.is_false(SymbolicNoneType().to_z3())

    def test_is_truthy(self) -> None:
        """Test is_truthy behavior."""
        assert z3.is_false(SymbolicNoneType().is_truthy())

    def test_is_falsy(self) -> None:
        """Test is_falsy behavior."""
        assert z3.is_true(SymbolicNoneType().is_falsy())

    def test_symbolic_eq(self) -> None:
        """Test symbolic_eq behavior."""
        assert z3.is_true(SymbolicNoneType().symbolic_eq(SymbolicNoneType()))
