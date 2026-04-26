import z3
import itertools

import pysymex.core.types.containers as mod
import pysymex.core.types.scalars as scalars_mod
from pysymex.core.types.scalars import SymbolicString, SymbolicValue


if not hasattr(scalars_mod, "next_address"):
    _next_addr_counter = itertools.count(1)
    setattr(scalars_mod, "next_address", lambda: next(_next_addr_counter))


class TestSymbolicList:
    def test_name(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        assert s.name == "lst"

    def test_to_z3(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        assert z3.is_array(s.to_z3())

    def test_hash_value(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        assert isinstance(s.hash_value(), int)

    def test_could_be_truthy(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        assert z3.is_bool(s.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        assert z3.is_bool(s.could_be_falsy())

    def test_copy(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        assert s.copy() is not s

    def test_symbolic(self) -> None:
        s, c = mod.SymbolicList.symbolic("lst")
        assert isinstance(s, mod.SymbolicList) and z3.is_bool(c)

    def test_from_const(self) -> None:
        s = mod.SymbolicList.from_const([1, 2])
        assert z3.is_int_value(s.z3_len)

    def test_empty(self) -> None:
        s = mod.SymbolicList.empty()
        assert z3.is_int_value(s.z3_len)

    def test_append(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        appended = s.append(SymbolicValue.from_const(1))
        assert isinstance(appended, mod.SymbolicList)

    def test_extend(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        out = s.extend([1, 2])
        assert isinstance(out, mod.SymbolicList)

    def test_length(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        assert z3.is_expr(s.length().z3_int)

    def test_in_bounds(self) -> None:
        s, _ = mod.SymbolicList.symbolic("lst")
        assert z3.is_bool(s.in_bounds(SymbolicValue.from_const(0)))

    def test_conditional_merge(self) -> None:
        a, _ = mod.SymbolicList.symbolic("a")
        b, _ = mod.SymbolicList.symbolic("b")
        merged = a.conditional_merge(b, z3.Bool("c"))
        assert merged is not None


class TestSymbolicDict:
    def test_name(self) -> None:
        d, _ = mod.SymbolicDict.symbolic("d")
        assert d.name == "d"

    def test_to_z3(self) -> None:
        d, _ = mod.SymbolicDict.symbolic("d")
        assert z3.is_array(d.to_z3())

    def test_copy(self) -> None:
        d, _ = mod.SymbolicDict.symbolic("d")
        assert d.copy() is not d

    def test_could_be_truthy(self) -> None:
        d, _ = mod.SymbolicDict.symbolic("d")
        assert z3.is_bool(d.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        d, _ = mod.SymbolicDict.symbolic("d")
        assert z3.is_bool(d.could_be_falsy())

    def test_hash_value(self) -> None:
        d, _ = mod.SymbolicDict.symbolic("d")
        assert isinstance(d.hash_value(), int)

    def test_symbolic(self) -> None:
        d, c = mod.SymbolicDict.symbolic("d")
        assert isinstance(d, mod.SymbolicDict) and z3.is_bool(c)

    def test_empty(self) -> None:
        assert isinstance(mod.SymbolicDict.empty(), mod.SymbolicDict)

    def test_from_const(self) -> None:
        d = mod.SymbolicDict.from_const({"a": 1})
        assert isinstance(d, mod.SymbolicDict)

    def test_update(self) -> None:
        d, _ = mod.SymbolicDict.symbolic("d")
        out, c = d.update({"k": 1})
        assert isinstance(out, mod.SymbolicDict) and z3.is_bool(c)

    def test_contains_key(self) -> None:
        d, _ = mod.SymbolicDict.symbolic("d")
        contains = d.contains_key(SymbolicString.from_const("k"))
        assert z3.is_bool(contains.z3_bool)

    def test_conditional_merge(self) -> None:
        a, _ = mod.SymbolicDict.symbolic("a")
        b, _ = mod.SymbolicDict.symbolic("b")
        assert a.conditional_merge(b, z3.Bool("c")) is not None


class TestSymbolicObject:
    def test_name(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert o.name == "o"

    def test_is_int(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_int)

    def test_is_bool(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_bool)

    def test_is_str(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_str)

    def test_is_none(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_none)

    def test_is_obj(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert z3.is_true(o.is_obj)

    def test_is_path(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_path)

    def test_to_z3(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert z3.is_expr(o.to_z3())

    def test_could_be_truthy(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert z3.is_bool(o.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert z3.is_bool(o.could_be_falsy())

    def test_symbolic(self) -> None:
        o, c = mod.SymbolicObject.symbolic("o", 1)
        assert isinstance(o, mod.SymbolicObject) and z3.is_bool(c)

    def test_from_const(self) -> None:
        o = mod.SymbolicObject.from_const(object())
        assert isinstance(o, mod.SymbolicObject)

    def test_conditional_merge(self) -> None:
        a, _ = mod.SymbolicObject.symbolic("a", -1)
        b, _ = mod.SymbolicObject.symbolic("b", -1)
        assert a.conditional_merge(b, z3.Bool("c")) is not None

    def test_hash_value(self) -> None:
        o, _ = mod.SymbolicObject.symbolic("o", -1)
        assert isinstance(o.hash_value(), int)


class TestSymbolicIterator:
    def test_name(self) -> None:
        it = mod.SymbolicIterator("it", [])
        assert it.name == "it"

    def test_to_z3(self) -> None:
        it = mod.SymbolicIterator("it", [])
        assert z3.is_int_value(it.to_z3())

    def test_hash_value(self) -> None:
        it = mod.SymbolicIterator("it", [])
        assert isinstance(it.hash_value(), int)

    def test_could_be_truthy(self) -> None:
        it = mod.SymbolicIterator("it", [])
        assert z3.is_true(it.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        it = mod.SymbolicIterator("it", [])
        assert z3.is_false(it.could_be_falsy())

    def test_advance(self) -> None:
        it = mod.SymbolicIterator("it", [])
        assert it.advance().index == 1
