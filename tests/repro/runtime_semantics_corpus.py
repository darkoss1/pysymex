"""Real-world Python semantics corpus used for edge-case regression testing."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
import copy
import heapq
import itertools


def case01_late_binding_lambdas() -> list[int]:
    """Return late-bound lambda outputs from a loop-comprehension capture."""
    funcs = [lambda: i for i in range(3)]
    return [fn() for fn in funcs]


def case02_default_bound_lambdas() -> list[int]:
    """Return correctly bound lambda outputs using default arguments."""
    funcs = [lambda i=i: i for i in range(3)]
    return [fn() for fn in funcs]


def case03_list_alias_append_len() -> int:
    """Return aliased list length after appending through one alias."""
    left: list[int] = []
    right = left
    right.append(1)
    return len(left)


def case04_list_alias_nested_mutation() -> int:
    """Return nested aliased list element after mutation through another alias."""
    base = [[0], [1]]
    alias = base
    alias[0].append(7)
    return base[0][-1]


def case05_dict_alias_shared_update() -> int:
    """Return dictionary value after alias-based mutation."""
    first = {"x": 1}
    second = first
    second["x"] = 9
    return first["x"]


def case06_shallow_copy_shares_nested() -> int:
    """Return nested value proving shallow copies share inner containers."""
    src = {"items": [1]}
    clone = src.copy()
    clone["items"].append(2)
    return src["items"][-1]


def case07_deep_copy_isolated_nested() -> tuple[int, int]:
    """Return source/clone lengths proving deep copies isolate inner containers."""
    src = {"items": [1]}
    clone = copy.deepcopy(src)
    clone["items"].append(2)
    return (len(src["items"]), len(clone["items"]))


def case08_mutable_default_persists() -> tuple[int, int]:
    """Return lengths showing mutable default arguments persist across calls."""

    def append_one(bucket: list[int] = []) -> int:
        """Append to a shared default bucket and return new length."""
        bucket.append(1)
        return len(bucket)

    return (append_one(), append_one())


def case09_safe_default_isolated() -> tuple[int, int]:
    """Return lengths showing explicit fresh defaults isolate call state."""

    def append_one(bucket: list[int] | None = None) -> int:
        """Append to a per-call bucket and return length."""
        target = [] if bucket is None else bucket
        target.append(1)
        return len(target)

    return (append_one(), append_one())


def case10_nonlocal_counter_progression() -> tuple[int, int, int]:
    """Return sequential increments produced by a nonlocal closure counter."""
    total = 0

    def bump() -> int:
        """Increment and return closure counter."""
        nonlocal total
        total += 1
        return total

    return (bump(), bump(), bump())


def case11_closure_factory_independence() -> tuple[int, int, int]:
    """Return values proving two closure instances maintain independent state."""

    def make_counter() -> Callable[[], int]:
        """Create a closure counter with isolated state."""
        value = 0

        def step() -> int:
            """Increment per-closure state and return it."""
            nonlocal value
            value += 1
            return value

        return step

    first = make_counter()
    second = make_counter()
    return (first(), first(), second())


def case12_list_slice_assignment() -> list[int]:
    """Return list after slice assignment replacing a middle segment."""
    values = [1, 2, 3, 4]
    values[1:3] = [8, 9]
    return values


def case13_extended_unpacking_middle() -> tuple[int, list[int], int]:
    """Return tuple with head/middle/tail from extended unpacking."""
    head, *middle, tail = [1, 2, 3, 4]
    return (head, middle, tail)


def case14_negative_index_lookup() -> int:
    """Return last list element using negative indexing."""
    values = [10, 20, 30]
    return values[-1]


def case15_list_multiply_alias_pitfall() -> tuple[int, int]:
    """Return two elements proving list multiplication aliases inner lists."""
    inner: list[int] = []
    rows: list[list[int]] = [inner] * 3
    rows[0].append(1)
    return (len(rows[0]), len(rows[1]))


def case16_list_comprehension_scope_isolated() -> bool:
    """Return True when comprehension variable does not leak to outer scope."""
    _ = [i for i in range(3)]
    return "i" in locals()


def case17_setdefault_alias_behavior() -> int:
    """Return dictionary length after mutating list obtained from setdefault."""
    mapping: dict[str, list[int]] = {}
    bucket = mapping.setdefault("items", [])
    bucket.append(1)
    return len(mapping["items"])


def case18_generator_consumption_once() -> tuple[int, int]:
    """Return sums proving generators are consumed and then exhausted."""
    source = (x for x in [1, 2, 3])
    first = sum(source)
    second = sum(source)
    return (first, second)


def case19_any_short_circuit_side_effect() -> int:
    """Return side-effect count showing any() short-circuits after truthy item."""
    count = 0

    def probe(value: bool) -> bool:
        """Count predicate evaluations and return value."""
        nonlocal count
        count += 1
        return value

    _ = any(probe(item) for item in [False, True, True])
    return count


def case20_bool_operand_return_semantics() -> tuple[str, str]:
    """Return values showing bool operators return operands, not coerced bools."""
    return ("left" and "right", "" or "fallback")


def case21_chained_comparison_truth() -> bool:
    """Return result of chained comparison evaluation."""
    return 1 < 2 < 3


def case22_divmod_identity_check() -> bool:
    """Return True when floor-division and modulus satisfy reconstruction identity."""
    numerator = 23
    denominator = 5
    quotient = numerator // denominator
    remainder = numerator % denominator
    return quotient * denominator + remainder == numerator


def case23_big_integer_precision() -> int:
    """Return big integer result proving arbitrary-precision integer arithmetic."""
    return (10**30) + 1 - (10**30)


def case24_bytes_slice_value() -> bytes:
    """Return byte slice from a bytes literal."""
    payload = b"abcdef"
    return payload[1:4]


def case25_bytearray_alias_mutation() -> int:
    """Return first element after aliasing and mutating a bytearray."""
    first = bytearray(b"\x01\x02")
    second = first
    second[0] = 9
    return first[0]


def case26_tuple_concat_new_object() -> tuple[int, int, int]:
    """Return tuple produced by concatenating immutable tuples."""
    start = (1, 2)
    return start + (3,)


def case27_dict_merge_precedence() -> int:
    """Return value proving right-hand dictionary wins merge conflicts."""
    left = {"x": 1, "y": 2}
    right = {"x": 9}
    merged = left | right
    return merged["x"]


def case28_try_finally_cleanup_order() -> str:
    """Return trace proving finally runs before function return completes."""
    trace: list[str] = []
    try:
        trace.append("try")
        return "->".join(trace)
    finally:
        trace.append("finally")


def case29_exception_handler_specificity() -> str:
    """Return handler label proving specific exception blocks take precedence."""
    try:
        raise KeyError("k")
    except KeyError:
        return "key"
    except Exception:
        return "generic"


@dataclass(slots=True)
class _Bag:
    """Dataclass used to verify default_factory isolation semantics."""

    items: list[int] = field(default_factory=list[int])


def case30_dataclass_default_factory_isolated() -> tuple[int, int]:
    """Return lengths proving dataclass default_factory creates isolated lists."""
    first = _Bag()
    second = _Bag()
    first.items.append(1)
    return (len(first.items), len(second.items))


def case31_sorting_stability() -> list[int]:
    """Return ids after stable sort preserving relative order of equal keys."""
    rows = [{"k": 1, "id": 0}, {"k": 1, "id": 1}, {"k": 0, "id": 2}]
    ordered = sorted(rows, key=lambda item: item["k"])
    return [item["id"] for item in ordered]


def case32_unicode_casefold_equivalence() -> bool:
    """Return True when Unicode casefold normalizes equivalent text."""
    return "Straße".casefold() == "strasse".casefold()


def case33_string_join_generator() -> str:
    """Return joined string from generator-produced tokens."""
    return "-".join(str(i) for i in range(3))


def case34_partition_semantics() -> tuple[str, str, str]:
    """Return partition tuple showing separator is preserved in output."""
    return "a=b=c".partition("=")


def case35_deque_rotate_front() -> int:
    """Return deque front element after rotation."""
    values: deque[int] = deque([1, 2, 3])
    values.rotate(1)
    return values[0]


def case36_heapq_smallest_after_pushes() -> int:
    """Return smallest value popped from a heap after multiple pushes."""
    heap: list[int] = []
    heapq.heappush(heap, 5)
    heapq.heappush(heap, 1)
    heapq.heappush(heap, 3)
    return heapq.heappop(heap)


def case37_groupby_requires_sorted_input() -> list[tuple[str, int]]:
    """Return grouped counts demonstrating itertools.groupby adjacency semantics."""
    values = ["a", "b", "a", "a"]
    return [(key, len(list(group))) for key, group in itertools.groupby(values)]


def case38_lru_cache_reuses_result() -> tuple[int, int]:
    """Return value/call-count proving lru_cache avoids repeated execution."""
    calls = 0

    @lru_cache(maxsize=None)
    def expensive(x: int) -> int:
        """Increment call counter and return deterministic computed value."""
        nonlocal calls
        calls += 1
        return x * 2

    value = expensive(7) + expensive(7)
    return (value, calls)


def case39_recursion_factorial_small() -> int:
    """Return factorial of five computed via recursion."""

    def factorial(n: int) -> int:
        """Return factorial of n for n >= 0."""
        if n <= 1:
            return 1
        return n * factorial(n - 1)

    return factorial(5)


def case40_matrix_alias_pattern() -> tuple[int, int]:
    """Return lengths proving repeated-list matrix rows alias one another."""
    matrix = [[0] * 2] * 2
    matrix[0].append(1)
    return (len(matrix[0]), len(matrix[1]))


def case41_tuple_unpack_swap() -> tuple[int, int]:
    """Return swapped tuple values using tuple unpack assignment."""
    left = 1
    right = 2
    left, right = right, left
    return (left, right)


def case42_list_extend_self_duplicate_length() -> int:
    """Return length after extending a list with itself."""
    values = [1, 2]
    values.extend(values)
    return len(values)


def case43_dict_pop_default_non_mutating() -> tuple[int, int]:
    """Return fallback and dict length proving pop with default does not add keys."""
    values = {"a": 1}
    fallback = values.pop("missing", 7)
    return (fallback, len(values))


def case44_set_intersection_update_result() -> set[int]:
    """Return set after in-place intersection update."""
    values = {1, 2, 3}
    values.intersection_update({2, 3, 4})
    return values


def case45_enumerate_start_offset() -> tuple[int, str]:
    """Return first enumerate pair with non-zero start offset."""
    return next(enumerate(["x", "y"], start=5))


def case46_zip_truncation_behavior() -> list[tuple[int, int]]:
    """Return zipped pairs showing zip truncates to shortest iterable."""
    return list(zip([1, 2, 3], [9, 8], strict=False))


def case47_walrus_assignment_expression() -> int:
    """Return value captured by assignment expression within a condition."""
    if (size := len([1, 2, 3])) > 0:
        return size
    return 0


def case48_closure_over_mutable_container() -> tuple[int, int]:
    """Return values proving closures over mutable containers observe mutations."""
    store = {"v": 1}

    def read() -> int:
        """Read shared mutable value from closure."""
        return store["v"]

    before = read()
    store["v"] = 9
    after = read()
    return (before, after)


def case49_nested_comprehension_flatten() -> list[int]:
    """Return flattened list from nested comprehension loops."""
    return [item for group in [[1, 2], [3]] for item in group]


def case50_reversed_iterator_snapshot() -> tuple[int, int]:
    """Return first two values from a reversed iterator."""
    iterator = reversed([1, 2, 3])
    first = next(iterator)
    second = next(iterator)
    return (first, second)
