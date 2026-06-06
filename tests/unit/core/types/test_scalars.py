import z3

import pytest

from pysymex.core.constants import Z3_ZERO
from pysymex.core.types.base import (
    SymbolicNoneType,
    SymbolicNoneType as SymbolicNone,
    SymbolicType,
    SymbolicType as BaseSymbolicType,
)
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue, fresh_name


def test_fresh_name() -> None:
    assert fresh_name("x").startswith("x_")


def test_symbolic_type_contract_uses_base_ssot() -> None:
    assert SymbolicType is BaseSymbolicType
    assert SymbolicNone is SymbolicNoneType
    assert isinstance(SymbolicValue.from_const(1), BaseSymbolicType)


class TestSymbolicType:
    def test_name(self) -> None:
        s = SymbolicString.from_const("x")
        assert s.name != ""

    def test_to_z3(self) -> None:
        s = SymbolicString.from_const("x")
        assert z3.is_expr(s.to_z3())

    def test_could_be_truthy(self) -> None:
        s = SymbolicString.from_const("x")
        assert z3.is_bool(s.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        s = SymbolicString.from_const("")
        assert z3.is_bool(s.could_be_falsy())

    def test_hash_value(self) -> None:
        s = SymbolicString.from_const("x")
        assert isinstance(s.hash_value(), int)


class TestSymbolicNone:
    def test_name(self) -> None:
        assert SymbolicNone().name == "None"

    def test_type_tag(self) -> None:
        assert SymbolicNone().type_tag == "NoneType"
        assert z3.is_true(SymbolicNone().is_none)

    def test_to_z3(self) -> None:
        assert z3.is_false(SymbolicNone().to_z3())

    def test_could_be_truthy(self) -> None:
        assert z3.is_false(SymbolicNone().could_be_truthy())

    def test_could_be_falsy(self) -> None:
        assert z3.is_true(SymbolicNone().could_be_falsy())

    def test_hash_value(self) -> None:
        assert isinstance(SymbolicNone().hash_value(), int)

    def test_conditional_merge(self) -> None:
        out = SymbolicNone().conditional_merge(SymbolicValue.from_const(1), z3.Bool("c"))
        assert out is not None


class TestSymbolicValue:
    def test_value(self) -> None:
        sv = SymbolicValue.from_const(7)
        assert sv.value == 7

    def test_name(self) -> None:
        sv = SymbolicValue.from_const(7)
        assert sv.name == "7"

    def test_type_tag(self) -> None:
        sv = SymbolicValue.from_const(7)
        assert sv.type_tag == "int"

    def test_to_z3(self) -> None:
        sv = SymbolicValue.from_const(7)
        assert z3.is_expr(sv.to_z3())

    def test_as_bv(self) -> None:
        sv = SymbolicValue.from_const(7)
        assert z3.is_bv(sv.as_bv)

    def test_hash_value(self) -> None:
        sv = SymbolicValue.from_const(7)
        assert isinstance(sv.hash_value(), int)

    def test_could_be_truthy(self) -> None:
        sv = SymbolicValue.from_const(1)
        assert z3.is_bool(sv.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        sv = SymbolicValue.from_const(0)
        assert z3.is_bool(sv.could_be_falsy())

    def test_conditional_merge(self) -> None:
        a = SymbolicValue.from_const(1)
        b = SymbolicValue.from_const(2)
        assert isinstance(a.conditional_merge(b, z3.Bool("c")), SymbolicValue)

    def test_as_string(self) -> None:
        sv = SymbolicValue.from_const("abc")
        assert isinstance(sv.as_string(), SymbolicString)

    def test_symbolic(self) -> None:
        sv, c = SymbolicValue.symbolic("x")
        assert isinstance(sv, SymbolicValue) and z3.is_bool(c)

    def test_symbolic_type_constraint_requires_exactly_one_type(self) -> None:
        sv, constraint = SymbolicValue.symbolic("exactly_one")
        type_vars = [
            sv.is_int,
            sv.is_bool,
            sv.is_str,
            sv.is_path,
            sv.is_obj,
            sv.is_none,
            sv.is_float,
            sv.is_list,
            sv.is_dict,
        ]

        all_false_solver = z3.Solver()
        all_false_solver.add(constraint, *[z3.Not(type_var) for type_var in type_vars])
        assert all_false_solver.check() == z3.unsat

        two_true_solver = z3.Solver()
        two_true_solver.add(constraint, sv.is_int, sv.is_bool)
        assert two_true_solver.check() == z3.unsat

        one_true_solver = z3.Solver()
        one_true_solver.add(
            constraint,
            sv.is_int,
            *[z3.Not(type_var) for type_var in type_vars[1:]],
        )
        assert one_true_solver.check() == z3.sat

    def test_symbolic_int(self) -> None:
        sv, c = SymbolicValue.symbolic_int("x")
        assert z3.is_true(c) and z3.is_true(sv.is_int)

    def test_symbolic_float(self) -> None:
        sv, c = SymbolicValue.symbolic_float("x")
        assert z3.is_true(c) and z3.is_true(sv.is_float)

    def test_symbolic_bool(self) -> None:
        sv, c = SymbolicValue.symbolic_bool("x")
        assert z3.is_true(c) and z3.is_true(sv.is_bool)

    def test_from_specialized(self) -> None:
        ss = SymbolicString.from_const("x")
        assert isinstance(SymbolicValue.from_specialized(ss), SymbolicValue)

    def test_from_const(self) -> None:
        assert isinstance(SymbolicValue.from_const(42), SymbolicValue)

    def test_from_z3(self) -> None:
        sv = SymbolicValue.from_z3(z3.Int("x"))
        assert isinstance(sv, SymbolicValue)

    def test_symbolic_path(self) -> None:
        sv, c = SymbolicValue.symbolic_path("p")
        assert isinstance(sv, SymbolicValue) and z3.is_bool(c)

    def test_logical_not(self) -> None:
        sv = SymbolicValue.from_const(True)
        assert isinstance(sv.logical_not(), SymbolicValue)

    @pytest.mark.parametrize(
        ("lhs", "rhs"),
        [
            (-(1 << 70), -(1 << 70)),
            (1 << 70, (1 << 65) - 1),
            (-(1 << 63) - 1, 1 << 63),
        ],
    )
    def test_concrete_bitwise_matches_python_unbounded_int(self, lhs: int, rhs: int) -> None:
        left = SymbolicValue.from_const(lhs)
        and_value = left & rhs
        or_value = left | rhs
        xor_value = left ^ rhs
        assert and_value.value == (lhs & rhs)
        assert or_value.value == (lhs | rhs)
        assert xor_value.value == (lhs ^ rhs)

    def test_bounded_nonnegative_xor_uses_unsigned_python_semantics(self) -> None:
        left = SymbolicValue(
            _name="left",
            z3_int=z3.Int("left"),
            is_int=z3.BoolVal(True),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            affinity_type="int",
            min_val=0,
            max_val=0xFFFFFFFF,
        )
        right = SymbolicValue(
            _name="right",
            z3_int=z3.Int("right"),
            is_int=z3.BoolVal(True),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            affinity_type="int",
            min_val=0,
            max_val=0x1FFFF,
        )

        out = left ^ right
        expected = z3.BV2Int(
            z3.Int2BV(left.z3_int, 32) ^ z3.Int2BV(right.z3_int, 32),
            is_signed=False,
        )
        solver = z3.Solver()
        solver.add(
            left.z3_int >= 0,
            left.z3_int <= 0xFFFFFFFF,
            right.z3_int >= 0,
            right.z3_int <= 0x1FFFF,
            out.z3_int != expected,
        )

        assert solver.check() == z3.unsat
        assert out.min_val == 0
        assert out.max_val == 0xFFFFFFFF

    @pytest.mark.parametrize(
        ("lhs", "rhs", "operator", "expected"),
        [
            (8, 1, "add", 9),
            (8, 3, "sub", 5),
            (8, 3, "mul", 24),
            (True, True, "add", 2),
            (1.5, 2, "mul", 3.0),
        ],
    )
    def test_concrete_additive_ops_retain_python_result_payload(
        self,
        lhs: int | float | bool,
        rhs: int | float | bool,
        operator: str,
        expected: int | float,
    ) -> None:
        left = SymbolicValue.from_const(lhs)

        if operator == "add":
            out = left + rhs
        elif operator == "sub":
            out = left - rhs
        else:
            out = left * rhs

        assert out.value == expected
        assert out.type_tag == type(expected).__name__

    def test_symbolic_additive_op_does_not_concretize_symbolic_operand(self) -> None:
        left, constraint = SymbolicValue.symbolic_int("left")

        out = left + 1

        assert z3.is_true(constraint)
        assert out.value is None
        assert z3.is_true(out.is_int)

    @pytest.mark.parametrize("shift", [-7, -1])
    def test_concrete_left_shift_negative_count_raises(self, shift: int) -> None:
        with pytest.raises(ValueError, match="negative shift count"):
            _ = SymbolicValue.from_const(3) << shift

    @pytest.mark.parametrize("shift", [-8, -1])
    def test_concrete_right_shift_negative_count_raises(self, shift: int) -> None:
        with pytest.raises(ValueError, match="negative shift count"):
            _ = SymbolicValue.from_const(3) >> shift

    def test_concrete_power_matches_python_exception_semantics(self) -> None:
        with pytest.raises(ZeroDivisionError):
            _ = SymbolicValue.from_const(0) ** -3

    def test_concrete_power_negative_exponent_returns_float(self) -> None:
        out = SymbolicValue.from_const(2) ** -2
        assert out.value == 0.25

    @pytest.mark.parametrize(
        ("lhs", "rhs", "message"),
        [
            (1, 0, "division by zero"),
            (1.0, 0.0, "float division by zero"),
            (1, 0.0, "float division by zero"),
            (1.0, 0, "float division by zero"),
        ],
    )
    def test_concrete_true_division_by_zero_matches_python(
        self, lhs: int | float, rhs: int | float, message: str
    ) -> None:
        with pytest.raises(ZeroDivisionError, match=message):
            _ = SymbolicValue.from_const(lhs) / rhs

    @pytest.mark.parametrize(
        ("lhs", "rhs"),
        [
            (3, 2),
            (3.0, 2),
            (True, 2),
        ],
    )
    def test_concrete_true_division_matches_python(
        self, lhs: int | float | bool, rhs: int | float | bool
    ) -> None:
        out = SymbolicValue.from_const(lhs) / rhs
        assert out.value == lhs / rhs
        assert out.type_tag == "float"

    def test_symbolic_true_division_uses_canonical_inactive_int_channel(self) -> None:
        left, _ = SymbolicValue.symbolic_int("left")
        right, _ = SymbolicValue.symbolic_int("right")
        out = left / right

        assert z3.eq(out.z3_int, Z3_ZERO)
        assert z3.is_false(out.is_int)
        assert z3.is_true(out.is_float)

    def test_symbolic_modulo_by_positive_constant_uses_direct_z3_mod(self) -> None:
        value, _ = SymbolicValue.symbolic_int("value")

        out = value % 2

        solver = z3.Solver()
        solver.add(out.z3_int != value.z3_int % 2)
        assert solver.check() == z3.unsat
        assert z3.is_true(out.is_int)

    def test_symbolic_floor_division_by_positive_constant_uses_direct_z3_division(self) -> None:
        value, _ = SymbolicValue.symbolic_int("value")

        out = value // 2

        solver = z3.Solver()
        solver.add(out.z3_int != value.z3_int / 2)
        assert solver.check() == z3.unsat
        assert z3.is_true(out.is_int)


class TestSymbolicString:
    def test_z3_str(self) -> None:
        s = SymbolicString.from_const("a")
        assert z3.is_string(s.z3_str)

    def test_z3_len(self) -> None:
        s = SymbolicString.from_const("a")
        assert z3.is_int(s.z3_len)

    def test_name(self) -> None:
        s = SymbolicString.from_const("a")
        assert s.name == "'a'"

    def test_type_tag(self) -> None:
        s = SymbolicString.from_const("a")
        assert s.type_tag == "str"
        assert z3.is_true(s.is_str)

    def test_to_z3(self) -> None:
        s = SymbolicString.from_const("a")
        assert z3.is_expr(s.to_z3())

    def test_could_be_truthy(self) -> None:
        s = SymbolicString.from_const("a")
        assert z3.is_bool(s.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        s = SymbolicString.from_const("")
        assert z3.is_bool(s.could_be_falsy())

    def test_hash_value(self) -> None:
        s = SymbolicString.from_const("a")
        assert isinstance(s.hash_value(), int)

    def test_symbolic(self) -> None:
        s, c = SymbolicString.symbolic("s")
        assert isinstance(s, SymbolicString) and z3.is_bool(c)

    def test_from_const(self) -> None:
        s = SymbolicString.from_const("x")
        assert isinstance(s, SymbolicString)

    def test_length(self) -> None:
        s = SymbolicString.from_const("abc")
        assert z3.is_int(s.length())

    def test_contains(self) -> None:
        s = SymbolicString.from_const("abc")
        out = s.contains("a")
        assert z3.is_bool(out.z3_bool)

    def test_startswith(self) -> None:
        s = SymbolicString.from_const("abc")
        out = s.startswith("a")
        assert z3.is_bool(out.z3_bool)

    def test_endswith(self) -> None:
        s = SymbolicString.from_const("abc")
        out = s.endswith("c")
        assert z3.is_bool(out.z3_bool)

    def test_substring(self) -> None:
        s = SymbolicString.from_const("abc")
        out = s.substring(0, 2)
        assert isinstance(out, SymbolicString)

    def test_conditional_merge(self) -> None:
        s = SymbolicString.from_const("a")
        out = s.conditional_merge(SymbolicValue.from_const("b"), z3.Bool("c"))
        assert isinstance(out, SymbolicValue)
