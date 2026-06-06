import z3
import pytest

from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.containers.sequences import SymbolicIterator, SymbolicSet
from pysymex.core.types.numeric.int import SymbolicInt
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue


class TestSymbolicList:
    def test_name(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        assert s.name == "lst"
        assert z3.is_true(s.is_list)

    def test_to_z3(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        assert z3.is_array(s.to_z3())

    def test_hash_value(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        assert isinstance(s.hash_value(), int)

    def test_could_be_truthy(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        assert z3.is_bool(s.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        assert z3.is_bool(s.could_be_falsy())

    def test_copy(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        assert s.copy() is not s

    def test_symbolic(self) -> None:
        s, c = SymbolicList.symbolic("lst")
        assert isinstance(s, SymbolicList) and z3.is_bool(c)

    def test_from_const(self) -> None:
        s = SymbolicList.from_const([1, 2])
        assert z3.is_int_value(s.z3_len)

    def test_empty(self) -> None:
        s = SymbolicList.empty()
        assert z3.is_int_value(s.z3_len)

    def test_append(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        appended = s.append(SymbolicValue.from_const(1))
        assert isinstance(appended, SymbolicList)
        # z3_len is an expression (lst_len + 1), not a constant value.
        assert z3.is_expr(appended.z3_len)

    def test_prepend(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        prepended = s.prepend(SymbolicValue.from_const(1))
        assert isinstance(prepended, SymbolicList)
        # In a symbolic list, we can't easily assert the value without a solver,
        # but we can check the Z3 expression structure if we really wanted to.
        # For now, asserting it returns a SymbolicList is the baseline.

    def test_rotate(self) -> None:
        s = SymbolicList.from_const([1, 2, 3])
        rotated = s.rotate(1)
        assert isinstance(rotated, SymbolicList)
        if rotated.concrete_items:
            assert rotated.concrete_items == [3, 1, 2]

    def test_extend(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        out = s.extend([1, 2])
        assert isinstance(out, SymbolicList)

    def test_length(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        assert z3.is_expr(s.length().z3_int)

    def test_in_bounds(self) -> None:
        s, _ = SymbolicList.symbolic("lst")
        assert z3.is_bool(s.in_bounds(SymbolicValue.from_const(0)))

    def test_in_bounds_accepts_valid_negative_index(self) -> None:
        s = SymbolicList.from_const([1, 2, 3])
        solver = z3.Solver()
        solver.add(s.in_bounds(SymbolicValue.from_const(-1)))
        assert solver.check() == z3.sat

    def test_setitem_preserves_concrete_items_for_negative_index(self) -> None:
        s = SymbolicList.from_const([1, 2, 3])
        updated = s.__setitem__(-1, 99)

        assert updated.concrete_items is not None
        assert updated.concrete_items[0] == 1
        assert updated.concrete_items[1] == 2
        replacement = updated.concrete_items[2]
        assert isinstance(replacement, SymbolicValue)
        assert replacement.value == 99

    def test_conditional_merge(self) -> None:
        a, _ = SymbolicList.symbolic("a")
        b, _ = SymbolicList.symbolic("b")
        merged = a.conditional_merge(b, z3.Bool("c"))
        assert merged is not None


class TestSymbolicDict:
    def test_name(self) -> None:
        d, _ = SymbolicDict.symbolic("d")
        assert d.name == "d"
        assert z3.is_true(d.is_dict)

    def test_to_z3(self) -> None:
        d, _ = SymbolicDict.symbolic("d")
        assert z3.is_array(d.to_z3())

    def test_copy(self) -> None:
        d, _ = SymbolicDict.symbolic("d")
        assert d.copy() is not d

    def test_could_be_truthy(self) -> None:
        d, _ = SymbolicDict.symbolic("d")
        assert z3.is_bool(d.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        d, _ = SymbolicDict.symbolic("d")
        assert z3.is_bool(d.could_be_falsy())

    def test_hash_value(self) -> None:
        d, _ = SymbolicDict.symbolic("d")
        assert isinstance(d.hash_value(), int)

    def test_symbolic(self) -> None:
        d, c = SymbolicDict.symbolic("d")
        assert isinstance(d, SymbolicDict) and z3.is_bool(c)

    def test_empty(self) -> None:
        assert isinstance(SymbolicDict.empty(), SymbolicDict)

    def test_from_const(self) -> None:
        d = SymbolicDict.from_const({"a": 1})
        assert isinstance(d, SymbolicDict)

    def test_contains_reports_definite_concrete_membership(self) -> None:
        d = SymbolicDict.from_const({"a": 1, 2: 3})

        assert "a" in d
        assert 2 in d

    def test_contains_reports_definite_concrete_absence(self) -> None:
        d = SymbolicDict.from_const({"a": 1})

        assert "missing" not in d

    def test_concrete_none_key_uses_symbolic_constant_payload_without_z3(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        d = SymbolicDict.from_const({None: 42})
        key = SymbolicValue.from_const(None)

        def fail_simplify(_expr: z3.ExprRef) -> z3.ExprRef:
            raise AssertionError("literal None key should avoid Z3 simplification")

        monkeypatch.setattr(z3, "simplify", fail_simplify)

        found, value = d.concrete_value_for_key(key)

        assert found
        assert value == 42

    def test_update(self) -> None:
        d, _ = SymbolicDict.symbolic("d")
        out, c = d.update({"k": 1})
        assert isinstance(out, SymbolicDict) and z3.is_bool(c)

    def test_contains_key(self) -> None:
        d, _ = SymbolicDict.symbolic("d")
        contains = d.contains_key(SymbolicString.from_const("k"))
        assert z3.is_bool(contains.z3_bool)

    def test_conditional_merge(self) -> None:
        a, _ = SymbolicDict.symbolic("a")
        b, _ = SymbolicDict.symbolic("b")
        assert a.conditional_merge(b, z3.Bool("c")) is not None


class TestSymbolicObject:
    def test_name(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert o.name == "o"

    def test_is_int(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_int)

    def test_is_bool(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_bool)

    def test_is_str(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_str)

    def test_is_none(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_none)

    def test_is_obj(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_true(o.is_obj)

    def test_is_path(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_path)

    def test_is_list(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_list)

    def test_is_dict(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_false(o.is_dict)

    def test_to_z3(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_expr(o.to_z3())

    def test_could_be_truthy(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_bool(o.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert z3.is_bool(o.could_be_falsy())

    def test_symbolic(self) -> None:
        o, c = SymbolicObject.symbolic("o", 1)
        assert isinstance(o, SymbolicObject) and z3.is_bool(c)

    def test_from_const(self) -> None:
        o = SymbolicObject.from_const(object())
        assert isinstance(o, SymbolicObject)

    def test_conditional_merge(self) -> None:
        a, _ = SymbolicObject.symbolic("a", -1)
        b, _ = SymbolicObject.symbolic("b", -1)
        assert a.conditional_merge(b, z3.Bool("c")) is not None

    def test_hash_value(self) -> None:
        o, _ = SymbolicObject.symbolic("o", -1)
        assert isinstance(o.hash_value(), int)


class TestSymbolicIterator:
    def test_name(self) -> None:
        it = SymbolicIterator("it", [])
        assert it.name == "it"

    def test_to_z3(self) -> None:
        it = SymbolicIterator("it", [])
        assert z3.is_int_value(it.to_z3())

    def test_hash_value(self) -> None:
        it = SymbolicIterator("it", [])
        assert isinstance(it.hash_value(), int)

    def test_could_be_truthy(self) -> None:
        it = SymbolicIterator("it", [])
        assert z3.is_true(it.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        it = SymbolicIterator("it", [])
        assert z3.is_false(it.could_be_falsy())

    def test_advance(self) -> None:
        it = SymbolicIterator("it", [])
        assert it.advance().index == 1

    def test_advanced_unknown_remaining_bound_gets_distinct_name(self) -> None:
        iterator = SymbolicIterator("it", iter([1]))
        advanced = iterator.advance()
        original_bound = iterator.remaining_bound()
        advanced_bound = advanced.remaining_bound()
        assert isinstance(original_bound, z3.ExprRef)
        assert isinstance(advanced_bound, z3.ExprRef)
        assert original_bound.sexpr() != advanced_bound.sexpr()


class TestSymbolicBytes:
    def test_name(self) -> None:
        b = SymbolicBytes.symbolic("b")
        assert b.name == "b"

    def test_to_z3(self) -> None:
        b = SymbolicBytes.symbolic("b")
        assert isinstance(b.to_z3(), z3.SeqRef)

    def test_hash_value(self) -> None:
        b = SymbolicBytes.symbolic("b")
        assert isinstance(b.hash_value(), int)

    def test_could_be_truthy(self) -> None:
        b = SymbolicBytes.symbolic("b")
        assert z3.is_bool(b.could_be_truthy())

    def test_could_be_falsy(self) -> None:
        b = SymbolicBytes.symbolic("b")
        assert z3.is_bool(b.could_be_falsy())

    def test_concrete_caching(self) -> None:
        b1 = SymbolicBytes.concrete(b"hello")
        b2 = SymbolicBytes.concrete(b"hello")
        assert b1 is b2  # Cache hits perfectly!

        b3 = SymbolicBytes.concrete(b"world")
        assert b1 is not b3  # Different bytes return different instances!


class TestSymbolicSet:
    def test_from_const_preserves_exact_integer_membership_and_length(self) -> None:
        s = SymbolicSet.from_const({1, 3})

        assert z3.is_true(s.contains(SymbolicInt.concrete(1)).z3_bool)
        assert z3.is_false(s.contains(SymbolicInt.concrete(2)).z3_bool)
        assert z3.is_int_value(s.length.z3_int)
        assert s.length.z3_int.as_long() == 2

    def test_concrete_backing_survives_definite_add_remove(self) -> None:
        s = SymbolicSet.from_const({1})
        updated = s.add(SymbolicInt.concrete(2)).remove(SymbolicInt.concrete(1))

        assert z3.is_false(updated.contains(SymbolicInt.concrete(1)).z3_bool)
        assert z3.is_true(updated.contains(SymbolicInt.concrete(2)).z3_bool)
        assert updated.length.z3_int.as_long() == 1
