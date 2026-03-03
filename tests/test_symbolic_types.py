"""Tests for the extended symbolic type system.

Tests cover:
1. Primitive types (int, bool, float, none, string, bytes)
2. Collection types (tuple, list, dict, set)
3. Type coercion
4. Arithmetic operations with type promotion
5. Comparison operations
6. Z3 integration
"""

import pytest

import z3


from pysymex.core.symbolic_types import (
    TypeTag,
    SymbolicType,
    SymbolicNoneType,
    SymbolicBool,
    SymbolicInt,
    SymbolicFloat,
    SymbolicString,
    SymbolicBytes,
    SYMBOLIC_NONE,
    SymbolicTuple,
    SymbolicList,
    SymbolicDict,
    SymbolicSet,
    coerce_to_bool,
    coerce_to_int,
    coerce_to_float,
    coerce_to_string,
    symbolic_from_python,
    symbolic_for_type,
    is_numeric,
    is_sequence,
    is_collection,
    get_common_type,
    fresh_name,
    reset_counters,
)


@pytest.fixture(autouse=True)
def reset_names():
    """Reset name counters before each test."""

    reset_counters()


def solve(constraint: z3.BoolRef) -> bool:
    """Check if constraint is satisfiable."""

    s = z3.Solver()

    s.add(constraint)

    return s.check() == z3.sat


def prove(constraint: z3.BoolRef) -> bool:
    """Check if constraint is always true."""

    s = z3.Solver()

    s.add(z3.Not(constraint))

    return s.check() == z3.unsat


class TestSymbolicNone:
    def test_singleton(self):
        assert SYMBOLIC_NONE is not None

        assert SYMBOLIC_NONE.type_tag == TypeTag.NONE

    def test_always_falsy(self):
        assert prove(SYMBOLIC_NONE.is_falsy())

        assert prove(z3.Not(SYMBOLIC_NONE.is_truthy()))

    def test_equality(self):
        none1 = SymbolicNoneType()

        none2 = SymbolicNoneType()

        assert prove(none1.symbolic_eq(none2))

        int_val = SymbolicInt.concrete(0)

        assert prove(z3.Not(none1.symbolic_eq(int_val)))


class TestSymbolicBool:
    def test_concrete_true(self):
        t = SymbolicBool.concrete(True)

        assert t.type_tag == TypeTag.BOOL

        assert prove(t.is_truthy())

        assert prove(z3.Not(t.is_falsy()))

    def test_concrete_false(self):
        f = SymbolicBool.concrete(False)

        assert prove(f.is_falsy())

        assert prove(z3.Not(f.is_truthy()))

    def test_symbolic(self):
        b = SymbolicBool.symbolic("test_bool")

        assert solve(b.is_truthy())

        assert solve(b.is_falsy())

    def test_and(self):
        t = SymbolicBool.concrete(True)

        f = SymbolicBool.concrete(False)

        assert prove((t & t).z3_bool)

        assert prove(z3.Not((t & f).z3_bool))

        assert prove(z3.Not((f & t).z3_bool))

        assert prove(z3.Not((f & f).z3_bool))

    def test_or(self):
        t = SymbolicBool.concrete(True)

        f = SymbolicBool.concrete(False)

        assert prove((t | t).z3_bool)

        assert prove((t | f).z3_bool)

        assert prove((f | t).z3_bool)

        assert prove(z3.Not((f | f).z3_bool))

    def test_not(self):
        t = SymbolicBool.concrete(True)

        f = SymbolicBool.concrete(False)

        assert prove((~t).z3_bool == f.z3_bool)

        assert prove((~f).z3_bool == t.z3_bool)

    def test_xor(self):
        t = SymbolicBool.concrete(True)

        f = SymbolicBool.concrete(False)

        assert prove(z3.Not((t ^ t).z3_bool))

        assert prove((t ^ f).z3_bool)

        assert prove((f ^ t).z3_bool)

        assert prove(z3.Not((f ^ f).z3_bool))

    def test_equality_with_int(self):
        t = SymbolicBool.concrete(True)

        one = SymbolicInt.concrete(1)

        zero = SymbolicInt.concrete(0)

        assert prove(t.symbolic_eq(one))

        f = SymbolicBool.concrete(False)

        assert prove(f.symbolic_eq(zero))


class TestSymbolicInt:
    def test_concrete(self):
        five = SymbolicInt.concrete(5)

        assert five.type_tag == TypeTag.INT

        assert prove(five.z3_int == 5)

    def test_symbolic(self):
        x = SymbolicInt.symbolic("x")

        assert solve(x.z3_int == 0)

        assert solve(x.z3_int == 100)

        assert solve(x.z3_int == -50)

    def test_truthiness(self):
        zero = SymbolicInt.concrete(0)

        five = SymbolicInt.concrete(5)

        neg = SymbolicInt.concrete(-3)

        assert prove(zero.is_falsy())

        assert prove(five.is_truthy())

        assert prove(neg.is_truthy())

    def test_addition(self):
        a = SymbolicInt.concrete(3)

        b = SymbolicInt.concrete(4)

        result = a + b

        assert isinstance(result, SymbolicInt)

        assert prove(result.z3_int == 7)

    def test_subtraction(self):
        a = SymbolicInt.concrete(10)

        b = SymbolicInt.concrete(3)

        result = a - b

        assert prove(result.z3_int == 7)

    def test_multiplication(self):
        a = SymbolicInt.concrete(3)

        b = SymbolicInt.concrete(4)

        result = a * b

        assert prove(result.z3_int == 12)

    def test_negation(self):
        a = SymbolicInt.concrete(5)

        result = -a

        assert prove(result.z3_int == -5)

    def test_abs(self):
        pos = SymbolicInt.concrete(5)

        neg = SymbolicInt.concrete(-5)

        assert prove(abs(pos).z3_int == 5)

        assert prove(abs(neg).z3_int == 5)

    def test_modulo(self):
        a = SymbolicInt.concrete(17)

        b = SymbolicInt.concrete(5)

        result = a % b

        assert prove(result.z3_int == 2)

    def test_floor_div(self):
        a = SymbolicInt.concrete(17)

        b = SymbolicInt.concrete(5)

        result = a // b

        assert prove(result.z3_int == 3)

    def test_true_div_returns_float(self):
        a = SymbolicInt.concrete(5)

        b = SymbolicInt.concrete(2)

        result = a / b

        assert isinstance(result, SymbolicFloat)

    def test_comparisons(self):
        a = SymbolicInt.concrete(5)

        b = SymbolicInt.concrete(3)

        assert prove((a > b).z3_bool)

        assert prove((a >= b).z3_bool)

        assert prove((b < a).z3_bool)

        assert prove((b <= a).z3_bool)

        assert prove(z3.Not((a == b).z3_bool))

        assert prove((a != b).z3_bool)

    def test_symbolic_arithmetic(self):
        x = SymbolicInt.symbolic("x")

        y = SymbolicInt.symbolic("y")

        assert prove((x + y).z3_int == (y + x).z3_int)

        assert prove(((x + y) - y).z3_int == x.z3_int)

    def test_add_with_float_promotes(self):
        i = SymbolicInt.concrete(3)

        f = SymbolicFloat.concrete(2.5)

        result = i + f

        assert isinstance(result, SymbolicFloat)


class TestSymbolicFloat:
    def test_concrete(self):
        f = SymbolicFloat.concrete(3.14)

        assert f.type_tag == TypeTag.FLOAT

    def test_symbolic(self):
        x = SymbolicFloat.symbolic("x")

        assert solve(x.z3_real == 0)

        assert solve(x.z3_real > 0)

        assert solve(x.z3_real < 0)

    def test_truthiness(self):
        zero = SymbolicFloat.concrete(0.0)

        pos = SymbolicFloat.concrete(3.14)

        assert prove(zero.is_falsy())

        assert prove(pos.is_truthy())

    def test_arithmetic(self):
        a = SymbolicFloat.concrete(2.5)

        b = SymbolicFloat.concrete(1.5)

        assert prove((a + b).z3_real == 4.0)

        assert prove((a - b).z3_real == 1.0)

        assert prove((a * b).z3_real == 3.75)

    def test_division(self):
        a = SymbolicFloat.concrete(5.0)

        b = SymbolicFloat.concrete(2.0)

        result = a / b

        assert prove(result.z3_real == 2.5)

    def test_negation(self):
        a = SymbolicFloat.concrete(3.5)

        assert prove((-a).z3_real == -3.5)

    def test_abs(self):
        neg = SymbolicFloat.concrete(-3.5)

        assert prove(abs(neg).z3_real == 3.5)

    def test_comparisons(self):
        a = SymbolicFloat.concrete(2.5)

        b = SymbolicFloat.concrete(1.5)

        assert prove((a > b).z3_bool)

        assert prove((b < a).z3_bool)

    def test_to_int(self):
        f = SymbolicFloat.concrete(3.7)

        i = f.to_int()

        assert isinstance(i, SymbolicInt)

        assert prove(i.z3_int == 3)

    def test_mixed_arithmetic_with_int(self):
        f = SymbolicFloat.concrete(2.5)

        i = SymbolicInt.concrete(2)

        result = f + i

        assert isinstance(result, SymbolicFloat)

        assert prove(result.z3_real == 4.5)

    def test_comparison_with_int(self):
        f = SymbolicFloat.concrete(2.5)

        i = SymbolicInt.concrete(2)

        assert prove((f > i).z3_bool)

        assert prove((i < f).z3_bool)


class TestSymbolicString:
    def test_concrete(self):
        s = SymbolicString.concrete("hello")

        assert s.type_tag == TypeTag.STRING

    def test_symbolic(self):
        s = SymbolicString.symbolic("s")

        assert solve(s.z3_str == z3.StringVal("test"))

        assert solve(z3.Length(s.z3_str) == 0)

        assert solve(z3.Length(s.z3_str) > 10)

    def test_truthiness(self):
        empty = SymbolicString.concrete("")

        nonempty = SymbolicString.concrete("hi")

        assert prove(empty.is_falsy())

        assert prove(nonempty.is_truthy())

    def test_length(self):
        s = SymbolicString.concrete("hello")

        length = s.length()

        assert prove(length.z3_int == 5)

    def test_concatenation(self):
        a = SymbolicString.concrete("hello")

        b = SymbolicString.concrete(" world")

        result = a + b

        assert prove(result.z3_str == z3.StringVal("hello world"))

    def test_indexing(self):
        s = SymbolicString.concrete("hello")

        char = s[SymbolicInt.concrete(0)]

        assert prove(char.z3_str == z3.StringVal("h"))

    def test_contains(self):
        s = SymbolicString.concrete("hello world")

        sub = SymbolicString.concrete("world")

        not_sub = SymbolicString.concrete("xyz")

        result = s.contains(sub)

        assert prove(result.z3_bool)

        result2 = s.contains(not_sub)

        assert prove(z3.Not(result2.z3_bool))

    def test_startswith(self):
        s = SymbolicString.concrete("hello world")

        prefix = SymbolicString.concrete("hello")

        assert prove(s.startswith(prefix).z3_bool)

    def test_endswith(self):
        s = SymbolicString.concrete("hello world")

        suffix = SymbolicString.concrete("world")

        assert prove(s.endswith(suffix).z3_bool)

    def test_find(self):
        s = SymbolicString.concrete("hello world")

        sub = SymbolicString.concrete("world")

        idx = s.find(sub)

        assert prove(idx.z3_int == 6)

    def test_slice(self):
        s = SymbolicString.concrete("hello")

        sliced = s.slice(SymbolicInt.concrete(1), SymbolicInt.concrete(3))

        assert prove(sliced.z3_str == z3.StringVal("ell"))

    def test_replace(self):
        s = SymbolicString.concrete("hello world")

        old = SymbolicString.concrete("world")

        new = SymbolicString.concrete("python")

        result = s.replace(old, new)

        assert prove(result.z3_str == z3.StringVal("hello python"))

    def test_comparison(self):
        a = SymbolicString.concrete("abc")

        b = SymbolicString.concrete("abd")

        assert prove((a < b).z3_bool)

    def test_equality(self):
        a = SymbolicString.concrete("hello")

        b = SymbolicString.concrete("hello")

        c = SymbolicString.concrete("world")

        assert prove((a == b).z3_bool)

        assert prove((a != c).z3_bool)


class TestSymbolicBytes:
    def test_concrete(self):
        b = SymbolicBytes.concrete(b"hello")

        assert b.type_tag == TypeTag.BYTES

    def test_symbolic(self):
        b = SymbolicBytes.symbolic("b")

        assert b.type_tag == TypeTag.BYTES

    def test_truthiness(self):
        empty = SymbolicBytes.concrete(b"")

        nonempty = SymbolicBytes.concrete(b"hi")

        assert prove(empty.is_falsy())

        assert prove(nonempty.is_truthy())

    def test_length(self):
        b = SymbolicBytes.concrete(b"hello")

        length = b.length()

        assert prove(length.z3_int == 5)

    def test_concatenation(self):
        a = SymbolicBytes.concrete(b"hello")

        b = SymbolicBytes.concrete(b" world")

        result = a + b

        assert result.type_tag == TypeTag.BYTES


class TestSymbolicTuple:
    def test_creation(self):
        t = SymbolicTuple.from_elements(
            SymbolicInt.concrete(1), SymbolicString.concrete("hello"), SymbolicBool.concrete(True)
        )

        assert t.type_tag == TypeTag.TUPLE

        assert len(t) == 3

    def test_empty_tuple(self):
        t = SymbolicTuple.empty()

        assert len(t) == 0

        assert prove(t.is_falsy())

    def test_truthiness(self):
        empty = SymbolicTuple.empty()

        nonempty = SymbolicTuple.from_elements(SymbolicInt.concrete(1))

        assert prove(empty.is_falsy())

        assert prove(nonempty.is_truthy())

    def test_indexing(self):
        t = SymbolicTuple.from_elements(
            SymbolicInt.concrete(10), SymbolicInt.concrete(20), SymbolicInt.concrete(30)
        )

        elem0 = t[0]

        elem1 = t[1]

        assert isinstance(elem0, SymbolicInt)

        assert prove(elem0.z3_int == 10)

        assert prove(elem1.z3_int == 20)

    def test_iteration(self):
        t = SymbolicTuple.from_elements(
            SymbolicInt.concrete(1), SymbolicInt.concrete(2), SymbolicInt.concrete(3)
        )

        values = list(t)

        assert len(values) == 3

    def test_concatenation(self):
        t1 = SymbolicTuple.from_elements(SymbolicInt.concrete(1))

        t2 = SymbolicTuple.from_elements(SymbolicInt.concrete(2))

        result = t1 + t2

        assert len(result) == 2

    def test_equality(self):
        t1 = SymbolicTuple.from_elements(SymbolicInt.concrete(1), SymbolicInt.concrete(2))

        t2 = SymbolicTuple.from_elements(SymbolicInt.concrete(1), SymbolicInt.concrete(2))

        t3 = SymbolicTuple.from_elements(SymbolicInt.concrete(1), SymbolicInt.concrete(3))

        assert prove(t1.symbolic_eq(t2))

        assert prove(z3.Not(t1.symbolic_eq(t3)))

    def test_length(self):
        t = SymbolicTuple.from_elements(
            SymbolicInt.concrete(1), SymbolicInt.concrete(2), SymbolicInt.concrete(3)
        )

        assert prove(t.length().z3_int == 3)


class TestSymbolicList:
    def test_concrete_int_list(self):
        lst = SymbolicList.concrete_int_list([1, 2, 3, 4, 5])

        assert lst.type_tag == TypeTag.LIST

    def test_symbolic_list(self):
        lst = SymbolicList.symbolic_int_list("items")

        assert lst.type_tag == TypeTag.LIST

    def test_truthiness(self):
        empty = SymbolicList.concrete_int_list([])

        nonempty = SymbolicList.concrete_int_list([1, 2, 3])

        assert prove(empty.is_falsy())

        assert prove(nonempty.is_truthy())

    def test_length(self):
        lst = SymbolicList.concrete_int_list([1, 2, 3])

        length = lst.length()

        assert prove(length.z3_int == 3)

    def test_indexing(self):
        lst = SymbolicList.concrete_int_list([10, 20, 30])

        elem = lst[SymbolicInt.concrete(1)]

        assert isinstance(elem, SymbolicInt)

    def test_concatenation(self):
        lst1 = SymbolicList.concrete_int_list([1, 2])

        lst2 = SymbolicList.concrete_int_list([3, 4])

        result = lst1 + lst2

        length = result.length()

        assert prove(length.z3_int == 4)

    def test_append(self):
        lst = SymbolicList.concrete_int_list([1, 2])

        new_lst = lst.append(SymbolicInt.concrete(3))

        assert prove(new_lst.length().z3_int == 3)

    def test_contains(self):
        lst = SymbolicList.concrete_int_list([1, 2, 3, 4, 5])

        result = lst.contains(SymbolicInt.concrete(3))

        assert prove(result.z3_bool)

        result2 = lst.contains(SymbolicInt.concrete(10))

        assert prove(z3.Not(result2.z3_bool))

    def test_equality(self):
        lst1 = SymbolicList.concrete_int_list([1, 2, 3])

        lst2 = SymbolicList.concrete_int_list([1, 2, 3])

        assert prove(lst1.symbolic_eq(lst2))


class TestSymbolicDict:
    def test_creation(self):
        d = SymbolicDict.symbolic_int_dict("mapping")

        assert d.type_tag == TypeTag.DICT

    def test_get_set(self):
        d = SymbolicDict.symbolic_int_dict()

        key = SymbolicInt.concrete(5)

        value = SymbolicInt.concrete(100)

        d2 = d.__setitem__(key, value)

        result = d2[key]

        assert prove(result.z3_int == 100)

    def test_equality(self):
        d1 = SymbolicDict.symbolic_int_dict("d1")

        d2 = SymbolicDict.symbolic_int_dict("d2")

        assert prove(d1.symbolic_eq(d1))


class TestSymbolicSet:
    def test_creation(self):
        s = SymbolicSet.symbolic_int_set("numbers")

        assert s.type_tag == TypeTag.SET

    def test_empty_set(self):
        s = SymbolicSet.empty_int_set()

        assert s.type_tag == TypeTag.SET

    def test_membership(self):
        s = SymbolicSet.empty_int_set()

        elem = SymbolicInt.concrete(5)

        result1 = s.contains(elem)

        assert prove(z3.Not(result1.z3_bool))

        s2 = s.add(elem)

        result2 = s2.contains(elem)

        assert prove(result2.z3_bool)

    def test_add_remove(self):
        s = SymbolicSet.empty_int_set()

        elem = SymbolicInt.concrete(5)

        s2 = s.add(elem)

        s3 = s2.remove(elem)

        result = s3.contains(elem)

        assert prove(z3.Not(result.z3_bool))

    def test_union(self):
        s1 = SymbolicSet.empty_int_set().add(SymbolicInt.concrete(1))

        s2 = SymbolicSet.empty_int_set().add(SymbolicInt.concrete(2))

        union = s1.union(s2)

        assert prove(union.contains(SymbolicInt.concrete(1)).z3_bool)

        assert prove(union.contains(SymbolicInt.concrete(2)).z3_bool)

    def test_intersection(self):
        s1 = SymbolicSet.empty_int_set().add(SymbolicInt.concrete(1)).add(SymbolicInt.concrete(2))

        s2 = SymbolicSet.empty_int_set().add(SymbolicInt.concrete(2)).add(SymbolicInt.concrete(3))

        inter = s1.intersection(s2)

        assert prove(inter.contains(SymbolicInt.concrete(2)).z3_bool)

        assert prove(z3.Not(inter.contains(SymbolicInt.concrete(1)).z3_bool))

        assert prove(z3.Not(inter.contains(SymbolicInt.concrete(3)).z3_bool))

    def test_difference(self):
        s1 = SymbolicSet.empty_int_set().add(SymbolicInt.concrete(1)).add(SymbolicInt.concrete(2))

        s2 = SymbolicSet.empty_int_set().add(SymbolicInt.concrete(2))

        diff = s1.difference(s2)

        assert prove(diff.contains(SymbolicInt.concrete(1)).z3_bool)

        assert prove(z3.Not(diff.contains(SymbolicInt.concrete(2)).z3_bool))

    def test_subset(self):
        s1 = SymbolicSet.empty_int_set().add(SymbolicInt.concrete(1))

        s2 = SymbolicSet.empty_int_set().add(SymbolicInt.concrete(1)).add(SymbolicInt.concrete(2))

        assert prove(s1.issubset(s2).z3_bool)

        assert prove(z3.Not(s2.issubset(s1).z3_bool))


class TestCoercion:
    def test_coerce_to_bool_from_int(self):
        zero = SymbolicInt.concrete(0)

        five = SymbolicInt.concrete(5)

        assert prove(z3.Not(coerce_to_bool(zero).z3_bool))

        assert prove(coerce_to_bool(five).z3_bool)

    def test_coerce_to_bool_from_float(self):
        zero = SymbolicFloat.concrete(0.0)

        pos = SymbolicFloat.concrete(3.14)

        assert prove(z3.Not(coerce_to_bool(zero).z3_bool))

        assert prove(coerce_to_bool(pos).z3_bool)

    def test_coerce_to_bool_from_string(self):
        empty = SymbolicString.concrete("")

        nonempty = SymbolicString.concrete("hello")

        assert prove(z3.Not(coerce_to_bool(empty).z3_bool))

        assert prove(coerce_to_bool(nonempty).z3_bool)

    def test_coerce_to_int_from_bool(self):
        t = SymbolicBool.concrete(True)

        f = SymbolicBool.concrete(False)

        assert prove(coerce_to_int(t).z3_int == 1)

        assert prove(coerce_to_int(f).z3_int == 0)

    def test_coerce_to_int_from_float(self):
        f = SymbolicFloat.concrete(3.7)

        i = coerce_to_int(f)

        assert prove(i.z3_int == 3)

    def test_coerce_to_float_from_int(self):
        i = SymbolicInt.concrete(5)

        f = coerce_to_float(i)

        assert prove(f.z3_real == 5.0)

    def test_coerce_to_float_from_bool(self):
        t = SymbolicBool.concrete(True)

        f = coerce_to_float(t)

        assert prove(f.z3_real == 1.0)

    def test_coerce_to_string_from_int(self):
        i = SymbolicInt.concrete(42)

        s = coerce_to_string(i)

        assert isinstance(s, SymbolicString)


class TestFactories:
    def test_symbolic_from_python_none(self):
        result = symbolic_from_python(None)

        assert result.type_tag == TypeTag.NONE

    def test_symbolic_from_python_bool(self):
        result = symbolic_from_python(True)

        assert result.type_tag == TypeTag.BOOL

    def test_symbolic_from_python_int(self):
        result = symbolic_from_python(42)

        assert result.type_tag == TypeTag.INT

        assert prove(result.z3_int == 42)

    def test_symbolic_from_python_float(self):
        result = symbolic_from_python(3.14)

        assert result.type_tag == TypeTag.FLOAT

    def test_symbolic_from_python_string(self):
        result = symbolic_from_python("hello")

        assert result.type_tag == TypeTag.STRING

    def test_symbolic_from_python_bytes(self):
        result = symbolic_from_python(b"hello")

        assert result.type_tag == TypeTag.BYTES

    def test_symbolic_from_python_tuple(self):
        result = symbolic_from_python((1, 2, 3))

        assert result.type_tag == TypeTag.TUPLE

        assert len(result) == 3

    def test_symbolic_from_python_list(self):
        result = symbolic_from_python([1, 2, 3])

        assert result.type_tag == TypeTag.LIST

    def test_symbolic_for_type_int(self):
        result = symbolic_for_type(int, "x")

        assert result.type_tag == TypeTag.INT

    def test_symbolic_for_type_float(self):
        result = symbolic_for_type(float, "x")

        assert result.type_tag == TypeTag.FLOAT

    def test_symbolic_for_type_str(self):
        result = symbolic_for_type(str, "s")

        assert result.type_tag == TypeTag.STRING

    def test_symbolic_for_type_list(self):
        result = symbolic_for_type(list, "items")

        assert result.type_tag == TypeTag.LIST


class TestUtilities:
    def test_is_numeric(self):
        assert is_numeric(SymbolicInt.concrete(5))

        assert is_numeric(SymbolicFloat.concrete(3.14))

        assert not is_numeric(SymbolicString.concrete("hello"))

        assert not is_numeric(SymbolicBool.concrete(True))

    def test_is_sequence(self):
        assert is_sequence(SymbolicString.concrete("hello"))

        assert is_sequence(SymbolicList.concrete_int_list([1, 2, 3]))

        assert is_sequence(SymbolicTuple.from_elements(SymbolicInt.concrete(1)))

        assert not is_sequence(SymbolicInt.concrete(5))

        assert not is_sequence(SymbolicDict.symbolic_int_dict())

    def test_is_collection(self):
        assert is_collection(SymbolicList.concrete_int_list([1]))

        assert is_collection(SymbolicTuple.from_elements(SymbolicInt.concrete(1)))

        assert is_collection(SymbolicDict.symbolic_int_dict())

        assert is_collection(SymbolicSet.symbolic_int_set())

        assert not is_collection(SymbolicString.concrete("hello"))

        assert not is_collection(SymbolicInt.concrete(5))

    def test_get_common_type(self):
        i = SymbolicInt.concrete(5)

        f = SymbolicFloat.concrete(3.14)

        b = SymbolicBool.concrete(True)

        assert get_common_type(i, i) == TypeTag.INT

        assert get_common_type(f, f) == TypeTag.FLOAT

        assert get_common_type(i, f) == TypeTag.FLOAT

        assert get_common_type(f, i) == TypeTag.FLOAT

        assert get_common_type(b, b) == TypeTag.BOOL


class TestNameGeneration:
    def testfresh_names_unique(self):
        names = [fresh_name("test") for _ in range(10)]

        assert len(names) == len(set(names))

    def testfresh_names_prefixed(self):
        name = fresh_name("myvar")

        assert name.startswith("myvar_")


class TestIntegration:
    def test_mixed_arithmetic_chain(self):
        """Test a chain of operations with type promotion."""

        a = SymbolicInt.concrete(5)

        b = SymbolicFloat.concrete(2.5)

        c = SymbolicInt.concrete(3)

        result = (a + b) * c

        assert isinstance(result, SymbolicFloat)

        assert prove(result.z3_real == 22.5)

    def test_symbolic_constraint_solving(self):
        """Test constraint solving with symbolic values."""

        x = SymbolicInt.symbolic("x")

        y = SymbolicInt.symbolic("y")

        s = z3.Solver()

        s.add((x + y).z3_int == 10)

        s.add((x > y).z3_bool)

        assert s.check() == z3.sat

        m = s.model()

        x_val = m.eval(x.z3_int).as_long()

        y_val = m.eval(y.z3_int).as_long()

        assert x_val + y_val == 10

        assert x_val > y_val

    def test_string_constraint_solving(self):
        """Test constraint solving with symbolic strings."""

        s = SymbolicString.symbolic("s")

        solver = z3.Solver()

        solver.add(z3.Length(s.z3_str) == 5)

        solver.add(z3.PrefixOf(z3.StringVal("he"), s.z3_str))

        assert solver.check() == z3.sat

    def test_list_constraint_solving(self):
        """Test constraint solving with symbolic lists."""

        lst = SymbolicList.symbolic_int_list("items")

        solver = z3.Solver()

        solver.add(z3.Length(lst.z3_seq) == 3)

        assert solver.check() == z3.sat

    def test_set_properties(self):
        """Test set algebraic properties."""

        s1 = SymbolicSet.symbolic_int_set("s1")

        s2 = SymbolicSet.symbolic_int_set("s2")

        u1 = s1.union(s2)

        u2 = s2.union(s1)

        assert prove(u1.symbolic_eq(u2))

        i1 = s1.intersection(s2)

        i2 = s2.intersection(s1)

        assert prove(i1.symbolic_eq(i2))
