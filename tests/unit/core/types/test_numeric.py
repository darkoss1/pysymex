import z3

from pysymex.core.types.scalars.values import int_to_bv, py_floor_div, py_mod
from pysymex.core.types.numeric.bool import SymbolicBool
from pysymex.core.types.numeric.float import SymbolicFloat
from pysymex.core.types.numeric.int import SymbolicInt


class TestSymbolicBool:
    def test_type_tag(self) -> None:
        b = SymbolicBool.symbolic("b")
        assert b.type_tag.name == "BOOL"
        assert z3.is_true(b.is_bool)

    def test_name(self) -> None:
        b = SymbolicBool.symbolic("myb")
        assert b.name == "myb"

    def test_to_z3(self) -> None:
        b = SymbolicBool.symbolic("b")
        assert z3.is_bool(b.to_z3())

    def test_is_truthy(self) -> None:
        b = SymbolicBool.symbolic("b")
        assert z3.is_bool(b.is_truthy())

    def test_is_falsy(self) -> None:
        b = SymbolicBool.symbolic("b")
        assert z3.is_bool(b.is_falsy())

    def test_execution_truthiness_queries_match_truthiness(self) -> None:
        b = SymbolicBool.symbolic("b")
        assert z3.eq(b.could_be_truthy(), b.is_truthy())
        assert z3.eq(b.could_be_falsy(), b.is_falsy())

    def test_symbolic_eq(self) -> None:
        b1 = SymbolicBool.symbolic("b1")
        b2 = SymbolicBool.symbolic("b2")
        assert z3.is_bool(b1.symbolic_eq(b2))

    def test_symbolic(self) -> None:
        assert isinstance(SymbolicBool.symbolic(), SymbolicBool)

    def test_concrete(self) -> None:
        b = SymbolicBool.concrete(True)
        assert z3.is_true(b.z3_bool)


class TestSymbolicInt:
    def test_type_tag(self) -> None:
        i = SymbolicInt.symbolic("i")
        assert i.type_tag.name == "INT"
        assert z3.is_true(i.is_int)

    def test_name(self) -> None:
        i = SymbolicInt.symbolic("myi")
        assert i.name == "myi"

    def test_to_z3(self) -> None:
        i = SymbolicInt.symbolic("i")
        assert z3.is_int(i.to_z3())

    def test_value(self) -> None:
        i = SymbolicInt.symbolic("i")
        assert i.value is i.z3_int

    def test_as_bv(self) -> None:
        i = SymbolicInt.symbolic("i")
        assert z3.is_bv(i.as_bv)
        assert z3.eq(i.as_bv, int_to_bv(i.z3_int))

    def test_is_truthy(self) -> None:
        i = SymbolicInt.symbolic("i")
        assert z3.is_bool(i.is_truthy())

    def test_is_falsy(self) -> None:
        i = SymbolicInt.symbolic("i")
        assert z3.is_bool(i.is_falsy())

    def test_execution_truthiness_queries_match_truthiness(self) -> None:
        i = SymbolicInt.symbolic("i")
        assert z3.eq(i.could_be_truthy(), i.is_truthy())
        assert z3.eq(i.could_be_falsy(), i.is_falsy())

    def test_symbolic_eq(self) -> None:
        i1 = SymbolicInt.symbolic("i1")
        i2 = SymbolicInt.symbolic("i2")
        assert z3.is_bool(i1.symbolic_eq(i2))

    def test_symbolic(self) -> None:
        assert isinstance(SymbolicInt.symbolic(), SymbolicInt)

    def test_concrete(self) -> None:
        i = SymbolicInt.concrete(7)
        assert z3.is_int_value(i.z3_int)

    def test_floor_division_reuses_python_semantics_helper(self) -> None:
        left = SymbolicInt.concrete(-3)
        right = SymbolicInt.concrete(2)
        result = left // right
        safe_divisor = z3.If(right.z3_int == 0, z3.IntVal(1), right.z3_int)
        expected = py_floor_div(left.z3_int, safe_divisor)
        assert z3.eq(result.z3_int, expected)
        assert z3.simplify(result.z3_int).as_long() == -2

    def test_modulo_reuses_python_semantics_helper(self) -> None:
        left = SymbolicInt.concrete(-3)
        right = SymbolicInt.concrete(2)
        result = left % right
        safe_divisor = z3.If(right.z3_int == 0, z3.IntVal(1), right.z3_int)
        expected = py_mod(left.z3_int, safe_divisor)
        assert z3.eq(result.z3_int, expected)
        assert z3.simplify(result.z3_int).as_long() == 1


class TestSymbolicFloat:
    def test_type_tag(self) -> None:
        f = SymbolicFloat.symbolic("f")
        assert f.type_tag.name == "FLOAT"
        assert z3.is_true(f.is_float)

    def test_name(self) -> None:
        f = SymbolicFloat.symbolic("myf")
        assert f.name == "myf"

    def test_to_z3(self) -> None:
        f = SymbolicFloat.symbolic("f")
        assert z3.is_real(f.to_z3())

    def test_is_truthy(self) -> None:
        f = SymbolicFloat.symbolic("f")
        assert z3.is_bool(f.is_truthy())

    def test_is_falsy(self) -> None:
        f = SymbolicFloat.symbolic("f")
        assert z3.is_bool(f.is_falsy())

    def test_execution_truthiness_queries_match_truthiness(self) -> None:
        f = SymbolicFloat.symbolic("f")
        assert z3.eq(f.could_be_truthy(), f.is_truthy())
        assert z3.eq(f.could_be_falsy(), f.is_falsy())

    def test_symbolic_eq(self) -> None:
        f1 = SymbolicFloat.symbolic("f1")
        f2 = SymbolicFloat.symbolic("f2")
        assert z3.is_bool(f1.symbolic_eq(f2))

    def test_to_int(self) -> None:
        f = SymbolicFloat.symbolic("f")
        assert isinstance(f.to_int(), SymbolicInt)

    def test_symbolic(self) -> None:
        assert isinstance(SymbolicFloat.symbolic(), SymbolicFloat)

    def test_concrete(self) -> None:
        f = SymbolicFloat.concrete(1.5)
        assert z3.is_rational_value(f.z3_real)
