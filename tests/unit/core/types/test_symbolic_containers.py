import z3

import pysymex.core.types.symbolic_containers as mod
from pysymex.core.types.numeric import SymbolicInt


class TestSymbolicString:
    def test_type_tag(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        assert s.type_tag.name == "STRING"

    def test_name(self) -> None:
        s = mod.SymbolicString.symbolic("abc")
        assert s.name == "abc"

    def test_to_z3(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        assert z3.is_string(s.to_z3())

    def test_is_truthy(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        assert z3.is_bool(s.is_truthy())

    def test_is_falsy(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        assert z3.is_bool(s.is_falsy())

    def test_symbolic_eq(self) -> None:
        assert z3.is_bool(
            mod.SymbolicString.symbolic("a").symbolic_eq(mod.SymbolicString.symbolic("b"))
        )

    def test_length(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        assert isinstance(s.length(), SymbolicInt)

    def test_contains(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        out = s.contains(mod.SymbolicString.concrete("x"))
        assert z3.is_bool(out.z3_bool)

    def test_startswith(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        assert z3.is_bool(s.startswith(mod.SymbolicString.concrete("a")).z3_bool)

    def test_endswith(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        assert z3.is_bool(s.endswith(mod.SymbolicString.concrete("a")).z3_bool)

    def test_find(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        assert isinstance(s.find(mod.SymbolicString.concrete("x")), SymbolicInt)

    def test_slice(self) -> None:
        s = mod.SymbolicString.symbolic("s")
        out = s.slice(SymbolicInt.concrete(0), SymbolicInt.concrete(1))
        assert isinstance(out, mod.SymbolicString)

    def test_replace(self) -> None:
        s = mod.SymbolicString.concrete("ab")
        out = s.replace(mod.SymbolicString.concrete("a"), mod.SymbolicString.concrete("x"))
        assert isinstance(out, mod.SymbolicString)

    def test_symbolic(self) -> None:
        assert isinstance(mod.SymbolicString.symbolic("s"), mod.SymbolicString)

    def test_concrete(self) -> None:
        assert isinstance(mod.SymbolicString.concrete("x"), mod.SymbolicString)


class TestSymbolicBytes:
    def test_type_tag(self) -> None:
        b = mod.SymbolicBytes.symbolic("b")
        assert b.type_tag.name == "BYTES"

    def test_name(self) -> None:
        b = mod.SymbolicBytes.symbolic("bytes_name")
        assert b.name == "bytes_name"

    def test_to_z3(self) -> None:
        b = mod.SymbolicBytes.symbolic("b")
        assert isinstance(b.to_z3(), z3.SeqRef)

    def test_is_truthy(self) -> None:
        b = mod.SymbolicBytes.symbolic("b")
        assert z3.is_bool(b.is_truthy())

    def test_is_falsy(self) -> None:
        b = mod.SymbolicBytes.symbolic("b")
        assert z3.is_bool(b.is_falsy())

    def test_symbolic_eq(self) -> None:
        b1 = mod.SymbolicBytes.symbolic("b1")
        b2 = mod.SymbolicBytes.symbolic("b2")
        assert z3.is_bool(b1.symbolic_eq(b2))

    def test_length(self) -> None:
        b = mod.SymbolicBytes.symbolic("b")
        assert isinstance(b.length(), SymbolicInt)

    def test_symbolic(self) -> None:
        assert isinstance(mod.SymbolicBytes.symbolic("b"), mod.SymbolicBytes)

    def test_concrete(self) -> None:
        assert isinstance(mod.SymbolicBytes.concrete(b"x"), mod.SymbolicBytes)


class TestSymbolicTuple:
    def test_type_tag(self) -> None:
        t = mod.SymbolicTuple.empty()
        assert t.type_tag.name == "TUPLE"

    def test_name(self) -> None:
        t = mod.SymbolicTuple.empty()
        assert isinstance(t.name, str)

    def test_to_z3(self) -> None:
        t = mod.SymbolicTuple.empty()
        assert z3.is_expr(t.to_z3())

    def test_is_truthy(self) -> None:
        t = mod.SymbolicTuple.from_elements(SymbolicInt.concrete(1))
        assert z3.is_true(t.is_truthy())

    def test_is_falsy(self) -> None:
        t = mod.SymbolicTuple.empty()
        assert z3.is_true(t.is_falsy())

    def test_symbolic_eq(self) -> None:
        t1 = mod.SymbolicTuple.from_elements(SymbolicInt.concrete(1))
        t2 = mod.SymbolicTuple.from_elements(SymbolicInt.concrete(2))
        assert z3.is_bool(t1.symbolic_eq(t2))

    def test_length(self) -> None:
        assert isinstance(mod.SymbolicTuple.empty().length(), SymbolicInt)

    def test_from_elements(self) -> None:
        t = mod.SymbolicTuple.from_elements(SymbolicInt.concrete(1))
        assert len(t.elements) == 1

    def test_empty(self) -> None:
        assert len(mod.SymbolicTuple.empty().elements) == 0


class TestSymbolicList:
    def test_type_tag(self) -> None:
        s = mod.SymbolicList.symbolic_int_list("l")
        assert s.type_tag.name == "LIST"

    def test_name(self) -> None:
        s = mod.SymbolicList.symbolic_int_list("l")
        assert s.name == "l"

    def test_to_z3(self) -> None:
        s = mod.SymbolicList.symbolic_int_list("l")
        assert isinstance(s.to_z3(), z3.SeqRef)

    def test_is_truthy(self) -> None:
        s = mod.SymbolicList.symbolic_int_list("l")
        assert z3.is_bool(s.is_truthy())

    def test_is_falsy(self) -> None:
        s = mod.SymbolicList.symbolic_int_list("l")
        assert z3.is_bool(s.is_falsy())

    def test_symbolic_eq(self) -> None:
        a = mod.SymbolicList.symbolic_int_list("a")
        b = mod.SymbolicList.symbolic_int_list("b")
        assert z3.is_bool(a.symbolic_eq(b))

    def test_length(self) -> None:
        assert isinstance(mod.SymbolicList.symbolic_int_list("l").length(), SymbolicInt)

    def test_append(self) -> None:
        out = mod.SymbolicList.symbolic_int_list("l").append(SymbolicInt.concrete(1))
        assert isinstance(out, mod.SymbolicList)

    def test_contains(self) -> None:
        s = mod.SymbolicList.symbolic_int_list("l")
        assert z3.is_bool(s.contains(SymbolicInt.concrete(1)).z3_bool)

    def test_slice(self) -> None:
        s = mod.SymbolicList.symbolic_int_list("l")
        out = s.slice(SymbolicInt.concrete(0), SymbolicInt.concrete(1))
        assert isinstance(out, mod.SymbolicList)

    def test_symbolic_int_list(self) -> None:
        assert isinstance(mod.SymbolicList.symbolic_int_list("x"), mod.SymbolicList)

    def test_concrete_int_list(self) -> None:
        assert isinstance(mod.SymbolicList.concrete_int_list([1, 2]), mod.SymbolicList)


class TestSymbolicDict:
    def test_type_tag(self) -> None:
        d = mod.SymbolicDict.symbolic_int_dict("d")
        assert d.type_tag.name == "DICT"

    def test_name(self) -> None:
        d = mod.SymbolicDict.symbolic_int_dict("d")
        assert d.name == "d"

    def test_to_z3(self) -> None:
        d = mod.SymbolicDict.symbolic_int_dict("d")
        assert z3.is_array(d.to_z3())

    def test_is_truthy(self) -> None:
        d = mod.SymbolicDict.symbolic_int_dict("d")
        assert z3.is_bool(d.is_truthy())

    def test_is_falsy(self) -> None:
        d = mod.SymbolicDict.symbolic_int_dict("d")
        assert z3.is_bool(d.is_falsy())

    def test_symbolic_eq(self) -> None:
        a = mod.SymbolicDict.symbolic_int_dict("a")
        b = mod.SymbolicDict.symbolic_int_dict("b")
        assert z3.is_bool(a.symbolic_eq(b))

    def test_get(self) -> None:
        d = mod.SymbolicDict.symbolic_int_dict("d")
        out = d.get(SymbolicInt.concrete(1), SymbolicInt.concrete(0))
        assert isinstance(out, SymbolicInt)

    def test_length(self) -> None:
        assert isinstance(mod.SymbolicDict.symbolic_int_dict("d").length, SymbolicInt)

    def test_contains(self) -> None:
        d = mod.SymbolicDict.symbolic_int_dict("d")
        assert z3.is_bool(d.contains(SymbolicInt.concrete(1)))

    def test_symbolic_int_dict(self) -> None:
        assert isinstance(mod.SymbolicDict.symbolic_int_dict("x"), mod.SymbolicDict)


class TestSymbolicSet:
    def test_type_tag(self) -> None:
        s = mod.SymbolicSet.symbolic_int_set("s")
        assert s.type_tag.name == "SET"

    def test_name(self) -> None:
        s = mod.SymbolicSet.symbolic_int_set("s")
        assert s.name == "s"

    def test_to_z3(self) -> None:
        s = mod.SymbolicSet.symbolic_int_set("s")
        assert z3.is_array(s.to_z3())

    def test_is_truthy(self) -> None:
        s = mod.SymbolicSet.symbolic_int_set("s")
        assert z3.is_bool(s.is_truthy())

    def test_is_falsy(self) -> None:
        s = mod.SymbolicSet.symbolic_int_set("s")
        assert z3.is_bool(s.is_falsy())

    def test_length(self) -> None:
        assert isinstance(mod.SymbolicSet.symbolic_int_set("s").length, SymbolicInt)

    def test_symbolic_eq(self) -> None:
        a = mod.SymbolicSet.symbolic_int_set("a")
        b = mod.SymbolicSet.symbolic_int_set("b")
        assert z3.is_bool(a.symbolic_eq(b))

    def test_contains(self) -> None:
        s = mod.SymbolicSet.symbolic_int_set("s")
        assert z3.is_bool(s.contains(SymbolicInt.concrete(1)).z3_bool)

    def test_add(self) -> None:
        s = mod.SymbolicSet.symbolic_int_set("s")
        assert isinstance(s.add(SymbolicInt.concrete(1)), mod.SymbolicSet)

    def test_remove(self) -> None:
        s = mod.SymbolicSet.symbolic_int_set("s")
        assert isinstance(s.remove(SymbolicInt.concrete(1)), mod.SymbolicSet)

    def test_union(self) -> None:
        a = mod.SymbolicSet.symbolic_int_set("a")
        b = mod.SymbolicSet.symbolic_int_set("b")
        assert isinstance(a.union(b), mod.SymbolicSet)

    def test_intersection(self) -> None:
        a = mod.SymbolicSet.symbolic_int_set("a")
        b = mod.SymbolicSet.symbolic_int_set("b")
        assert isinstance(a.intersection(b), mod.SymbolicSet)

    def test_difference(self) -> None:
        a = mod.SymbolicSet.symbolic_int_set("a")
        b = mod.SymbolicSet.symbolic_int_set("b")
        assert isinstance(a.difference(b), mod.SymbolicSet)

    def test_issubset(self) -> None:
        a = mod.SymbolicSet.symbolic_int_set("a")
        b = mod.SymbolicSet.symbolic_int_set("b")
        assert z3.is_bool(a.issubset(b).z3_bool)

    def test_symbolic_int_set(self) -> None:
        assert isinstance(mod.SymbolicSet.symbolic_int_set("x"), mod.SymbolicSet)

    def test_empty_int_set(self) -> None:
        assert isinstance(mod.SymbolicSet.empty_int_set(), mod.SymbolicSet)
