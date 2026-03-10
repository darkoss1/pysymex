import z3

from pysymex.core.types import SymbolicList, SymbolicString, SymbolicValue


def test_arithmetic_taint_propagation():
    a = SymbolicValue.from_const(10).with_taint("a")
    b = SymbolicValue.from_const(20).with_taint("b")
    c = SymbolicValue.from_const(30)  # clean

    # Binary ops
    res = a + b
    assert res.taint_labels == frozenset({"a", "b"})

    res = a + c
    assert res.taint_labels == frozenset({"a"})

    res = a * b
    assert res.taint_labels == frozenset({"a", "b"})

    res = -a
    assert res.taint_labels == frozenset({"a"})


def test_comparison_taint_propagation():
    a = SymbolicValue.from_const(10).with_taint("a")
    b = SymbolicValue.from_const(20)

    res = a < b
    assert res.taint_labels == frozenset({"a"})

    res = a == b
    assert res.taint_labels == frozenset({"a"})


def test_string_taint_propagation():
    s1 = SymbolicString.from_const("hello").with_taint("s1")
    s2 = SymbolicString.from_const("world")

    res = s1 + s2
    assert res.taint_labels == frozenset({"s1"})

    # substring
    start = SymbolicValue.from_const(0)
    end = SymbolicValue.from_const(1)
    res = s1.substring(start, end)
    assert res.taint_labels == frozenset({"s1"})


def test_container_taint_propagation():
    l = SymbolicList.from_const([1, 2, 3])
    val = SymbolicValue.from_const(4).with_taint("tainted_val")

    # Append tainted value -> list becomes tainted
    l_new = l.append(val)
    print(f"List taint: {l_new.taint_labels}")
    assert "tainted_val" in l_new.taint_labels  # type: ignore[reportOperatorIssue]

    # Accessing clean index from tainted list -> result is tainted (container policy)
    item = l_new[SymbolicValue.from_const(0)]
    assert "tainted_val" in item.taint_labels  # type: ignore[reportOperatorIssue]


def test_conditional_merge_taint():
    a = SymbolicValue.from_const(1).with_taint("a")
    b = SymbolicValue.from_const(2).with_taint("b")
    cond = z3.Bool("cond")

    res = a.conditional_merge(b, cond)
    assert res.taint_labels == frozenset({"a", "b"})
