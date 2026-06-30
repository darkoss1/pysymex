from __future__ import annotations

from pysymex._internal.analysis.scan.preflight.witness.core import (
    find_concrete_witness,
)


def _kinds(source: str) -> list[str]:
    return [str(issue["kind"]) for issue in find_concrete_witness(source)]


def test_concrete_witness_does_not_trust_declared_expected_bug_kinds() -> None:
    source = """
# pysymex-adversarial-test
# expected_bug_kinds: DIVISION_BY_ZERO

def target(x: int) -> int:
    return x + 1
"""

    assert _kinds(source) == []


def test_concrete_witness_treats_builtin_type_objects_as_globals() -> None:
    source = """
from collections import defaultdict

def target() -> int:
    state = defaultdict(int)
    return state["missing"] + 1

target()
"""

    assert "NAME_ERROR" not in _kinds(source)


def test_concrete_witness_reaches_hash_bit_count_division() -> None:
    source = """
def target(a: int, b: int) -> int:
    state = ((a ^ b) << 2) & 15
    if state.bit_count() == 0:
        return 100 // state
    return state

target(4, 4)
"""

    assert "DIVISION_BY_ZERO" in _kinds(source)


def test_concrete_witness_reaches_ord_license_division() -> None:
    source = """
_WITNESS_BYTES: list[int] = [0, 4, 0, 4]

def target(license_key: str) -> int:
    state = 0
    for index, char in enumerate(license_key):
        state ^= (ord(char) + index) & 7
    if license_key.startswith("\\x00") and state == 0:
        return 100 // state
    return state

if __name__ == "__main__":
    witness = bytes(_WITNESS_BYTES).decode("latin-1")
    target(witness)
"""

    assert "DIVISION_BY_ZERO" in _kinds(source)


def test_concrete_witness_derives_fully_pinned_short_string() -> None:
    source = """
def target(s: str) -> int:
    if len(s) == 4 and ord(s[0]) + 2 * ord(s[1]) + 3 * ord(s[2]) + 4 * ord(s[3]) == 670:
        if s[0] == "A" and s[1] == "B" and s[2] == "C" and s[3] == "D":
            return 1 // (ord(s[0]) - 65)
    return 1
"""

    issues = find_concrete_witness(source)

    assert [issue["kind"] for issue in issues] == ["DIVISION_BY_ZERO"]
    assert issues[0]["counterexample"] == {"s": "ABCD"}


def test_concrete_witness_rejects_infeasible_pinned_string_path() -> None:
    source = """
def target(s: str) -> int:
    if len(s) == 4 and ord(s[0]) + 2 * ord(s[1]) + 3 * ord(s[2]) + 4 * ord(s[3]) == 650:
        if s[0] == "A" and s[1] == "B" and s[2] == "C" and s[3] == "D":
            return 1 // (ord(s[0]) - 65)
    return 1
"""

    assert _kinds(source) == []


def test_concrete_witness_requires_every_index_for_length_derived_string() -> None:
    source = """
def target(s: str) -> int:
    if len(s) == 4 and s[0] == "A" and s[3] == "D":
        return 1 // (ord(s[0]) - 65)
    return 1
"""

    assert _kinds(source) == []


def test_concrete_witness_pinned_string_safe_control_stays_clean() -> None:
    source = """
def target(s: str) -> int:
    if s == "AZ":
        return 1 // (ord(s[0]) - 64)
    return 1
"""

    assert _kinds(source) == []


def test_concrete_witness_allows_deep_terminating_recursion() -> None:
    source = """
def recurse(n: int) -> int:
    if n == 0:
        return 1 // n
    return recurse(n - 1)

recurse(30)
"""

    assert _kinds(source) == ["DIVISION_BY_ZERO"]


def test_concrete_witness_stops_exact_recursive_recurrence() -> None:
    source = """
def recurse(n: int) -> int:
    return recurse(n)

recurse(1)
"""

    assert _kinds(source) == []


def test_concrete_witness_derives_fully_pinned_string_beyond_old_length_cap() -> None:
    witness = "abcdefghijklmnopq"
    indexed_guards = " and ".join(
        f"s[{index}] == {character!r}" for index, character in enumerate(witness)
    )
    source = (
        "def target(s: str) -> int:\n"
        f"    if len(s) == {len(witness)} and {indexed_guards}:\n"
        "        return 1 // (ord(s[0]) - 97)\n"
        "    return 1\n"
    )

    assert _kinds(source) == ["DIVISION_BY_ZERO"]
