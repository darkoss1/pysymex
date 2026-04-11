import z3
import itertools

import pysymex.core.types.scalars as mod


if not hasattr(mod, "next_address"):
    _next_addr_counter = itertools.count(1)
    setattr(mod, "next_address", lambda: next(_next_addr_counter))


def test_fresh_name() -> None:
    assert mod.fresh_name("x").startswith("x_")


class TestSymbolicType:
    def test_name(self) -> None:
        s = mod.SymbolicString.from_const("x")
        assert s.name != ""

    def test_to_z3(self) -> None:
        s = mod.SymbolicString.from_const("x")
        assert z3.is_expr(s.to_z3())

    def test_could_be_truthy(self) -> None:
        s = mod.SymbolicString.from_const("x")
        assert z3.is_bool(s.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        s = mod.SymbolicString.from_const("")
        assert z3.is_bool(s.could_be_falsy())

    def test_hash_value(self) -> None:
        s = mod.SymbolicString.from_const("x")
        assert isinstance(s.hash_value(), int)


class TestSymbolicNone:
    def test_name(self) -> None:
        assert mod.SymbolicNone().name == "None"

    def test_type_tag(self) -> None:
        assert mod.SymbolicNone().type_tag == "NoneType"

    def test_to_z3(self) -> None:
        assert z3.is_false(mod.SymbolicNone().to_z3())

    def test_could_be_truthy(self) -> None:
        assert z3.is_false(mod.SymbolicNone().could_be_truthy())

    def test_could_be_falsy(self) -> None:
        assert z3.is_true(mod.SymbolicNone().could_be_falsy())

    def test_hash_value(self) -> None:
        assert isinstance(mod.SymbolicNone().hash_value(), int)

    def test_as_unified(self) -> None:
        unified = mod.SymbolicNone().as_unified()
        assert z3.is_bool(unified.is_none)

    def test_conditional_merge(self) -> None:
        out = mod.SymbolicNone().conditional_merge(mod.SymbolicValue.from_const(1), z3.Bool("c"))
        assert out is not None


class TestSymbolicValue:
    def test_value(self) -> None:
        sv = mod.SymbolicValue.from_const(7)
        assert sv.value == 7

    def test_name(self) -> None:
        sv = mod.SymbolicValue.from_const(7)
        assert sv.name == "7"

    def test_type_tag(self) -> None:
        sv = mod.SymbolicValue.from_const(7)
        assert sv.type_tag == "int"

    def test_to_z3(self) -> None:
        sv = mod.SymbolicValue.from_const(7)
        assert z3.is_expr(sv.to_z3())

    def test_as_bv(self) -> None:
        sv = mod.SymbolicValue.from_const(7)
        assert z3.is_bv(sv.as_bv)

    def test_hash_value(self) -> None:
        sv = mod.SymbolicValue.from_const(7)
        assert isinstance(sv.hash_value(), int)

    def test_could_be_truthy(self) -> None:
        sv = mod.SymbolicValue.from_const(1)
        assert z3.is_bool(sv.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        sv = mod.SymbolicValue.from_const(0)
        assert z3.is_bool(sv.could_be_falsy())

    def test_with_taint(self) -> None:
        sv = mod.SymbolicValue.from_const(1).with_taint("input")
        assert sv.taint_labels is not None

    def test_conditional_merge(self) -> None:
        a = mod.SymbolicValue.from_const(1)
        b = mod.SymbolicValue.from_const(2)
        assert isinstance(a.conditional_merge(b, z3.Bool("c")), mod.SymbolicValue)

    def test_as_string(self) -> None:
        sv = mod.SymbolicValue.from_const("abc")
        assert isinstance(sv.as_string(), mod.SymbolicString)

    def test_as_unified(self) -> None:
        sv = mod.SymbolicValue.from_const(1)
        assert sv.as_unified() is sv

    def test_symbolic(self) -> None:
        sv, c = mod.SymbolicValue.symbolic("x")
        assert isinstance(sv, mod.SymbolicValue) and z3.is_bool(c)

    def test_symbolic_int(self) -> None:
        sv, c = mod.SymbolicValue.symbolic_int("x")
        assert z3.is_true(c) and z3.is_true(sv.is_int)

    def test_symbolic_bool(self) -> None:
        sv, c = mod.SymbolicValue.symbolic_bool("x")
        assert z3.is_true(c) and z3.is_true(sv.is_bool)

    def test_from_specialized(self) -> None:
        ss = mod.SymbolicString.from_const("x")
        assert isinstance(mod.SymbolicValue.from_specialized(ss), mod.SymbolicValue)

    def test_from_const(self) -> None:
        assert isinstance(mod.SymbolicValue.from_const(42), mod.SymbolicValue)

    def test_from_z3(self) -> None:
        sv = mod.SymbolicValue.from_z3(z3.Int("x"))
        assert isinstance(sv, mod.SymbolicValue)

    def test_symbolic_path(self) -> None:
        sv, c = mod.SymbolicValue.symbolic_path("p")
        assert isinstance(sv, mod.SymbolicValue) and z3.is_bool(c)

    def test_logical_not(self) -> None:
        sv = mod.SymbolicValue.from_const(True)
        assert isinstance(sv.logical_not(), mod.SymbolicValue)


class TestSymbolicString:
    def test_z3_str(self) -> None:
        s = mod.SymbolicString.from_const("a")
        assert z3.is_string(s.z3_str)

    def test_z3_len(self) -> None:
        s = mod.SymbolicString.from_const("a")
        assert z3.is_int(s.z3_len)

    def test_name(self) -> None:
        s = mod.SymbolicString.from_const("a")
        assert s.name == "'a'"

    def test_type_tag(self) -> None:
        s = mod.SymbolicString.from_const("a")
        assert s.type_tag == "str"

    def test_to_z3(self) -> None:
        s = mod.SymbolicString.from_const("a")
        assert z3.is_expr(s.to_z3())

    def test_could_be_truthy(self) -> None:
        s = mod.SymbolicString.from_const("a")
        assert z3.is_bool(s.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        s = mod.SymbolicString.from_const("")
        assert z3.is_bool(s.could_be_falsy())

    def test_hash_value(self) -> None:
        s = mod.SymbolicString.from_const("a")
        assert isinstance(s.hash_value(), int)

    def test_as_unified(self) -> None:
        s = mod.SymbolicString.from_const("a")
        assert z3.is_bool(s.as_unified().is_str)

    def test_symbolic(self) -> None:
        s, c = mod.SymbolicString.symbolic("s")
        assert isinstance(s, mod.SymbolicString) and z3.is_bool(c)

    def test_from_const(self) -> None:
        s = mod.SymbolicString.from_const("x")
        assert isinstance(s, mod.SymbolicString)

    def test_with_taint(self) -> None:
        s = mod.SymbolicString.from_const("x").with_taint("t")
        assert s.taint_labels is not None

    def test_length(self) -> None:
        s = mod.SymbolicString.from_const("abc")
        assert z3.is_int(s.length())

    def test_contains(self) -> None:
        s = mod.SymbolicString.from_const("abc")
        out = s.contains("a")
        assert z3.is_bool(out.z3_bool)

    def test_startswith(self) -> None:
        s = mod.SymbolicString.from_const("abc")
        out = s.startswith("a")
        assert z3.is_bool(out.z3_bool)

    def test_endswith(self) -> None:
        s = mod.SymbolicString.from_const("abc")
        out = s.endswith("c")
        assert z3.is_bool(out.z3_bool)

    def test_substring(self) -> None:
        s = mod.SymbolicString.from_const("abc")
        out = s.substring(0, 2)
        assert isinstance(out, mod.SymbolicString)

    def test_conditional_merge(self) -> None:
        s = mod.SymbolicString.from_const("a")
        out = s.conditional_merge(mod.SymbolicValue.from_const("b"), z3.Bool("c"))
        assert isinstance(out, mod.SymbolicValue)
