"""Runtime detector benchmark corpus with buggy and clean function pairs.

Each detector has:
- one positive sample that should trigger the detector
- one negative sample that should not trigger the detector
"""

from __future__ import annotations


def assertion_error_positive(x: int) -> int:
    """Trigger assertion-error by allowing symbolic violation of the asserted predicate."""
    assert x > 0
    return x


def assertion_error_negative() -> int:
    """Avoid assertion-error by using a tautological assertion on concrete values."""
    assert 1 == 1
    return 1


def attribute_error_positive() -> int:
    """Trigger attribute-error by loading a missing attribute from a concrete int."""
    value = 1
    return value.missing_attribute  # type: ignore[attr-defined]  # Intentional bug corpus sample.


def attribute_error_negative() -> int:
    """Avoid attribute-error by using a valid int attribute."""
    value = 1
    return value.bit_length()


def division_by_zero_positive(x: int) -> float:
    """Trigger division-by-zero by dividing by an unconstrained symbolic integer."""
    return 10.0 / x


def division_by_zero_negative() -> float:
    """Avoid division-by-zero by using a concrete non-zero divisor."""
    return 10.0 / 2.0


def _rare_path_gate(a: int, b: int, c: int, d: int, e: int, f: int) -> bool:
    """Return True only on a single rare symbolic branch pattern."""
    return (a > 0) and (b <= 0) and (c > 0) and (d <= 0) and (e > 0) and (f <= 0)


def division_by_zero_path_explosion_positive(
    a: int, b: int, c: int, d: int, e: int, f: int, x: int
) -> float:
    """Trigger division-by-zero behind a 1-of-64 rare path in branch-heavy logic."""
    denominator = 2
    if _rare_path_gate(a, b, c, d, e, f):
        denominator = x - x
    elif a + c > b + d:
        denominator = 3
    else:
        denominator = 5
    return 120.0 / denominator


def division_by_zero_path_explosion_negative(
    a: int, b: int, c: int, d: int, e: int, f: int
) -> float:
    """Avoid division-by-zero even with 64-path branching and nested conditions."""
    if _rare_path_gate(a, b, c, d, e, f):
        denominator = 1
    elif a + c > b + d:
        denominator = 3
    else:
        denominator = 7
    return 120.0 / denominator


def index_error_positive(i: int) -> int:
    """Trigger index-error via unconstrained symbolic index on a fixed-size list."""
    values = [10, 20, 30]
    return values[i]


def index_error_negative() -> int:
    """Avoid index-error by using an in-range concrete list index."""
    values = [10, 20, 30]
    return values[1]


def index_error_pop_empty_positive() -> int:
    """Trigger index-error by popping from an empty list without an explicit index."""
    values: list[int] = []
    return values.pop()


def index_error_pop_nonempty_negative() -> int:
    """Avoid index-error by popping from a known nonempty list."""
    values = [10]
    return values.pop()


def key_error_positive(k: str) -> int:
    """Trigger key-error by indexing a concrete dict with an unconstrained symbolic key."""
    mapping = {"a": 1}
    return mapping[k]


def key_error_negative() -> int:
    """Avoid key-error by indexing a concrete dict with an existing concrete key."""
    mapping = {"a": 1}
    return mapping["a"]


def none_dereference_positive() -> int:
    """Trigger none-dereference by accessing an attribute on None."""
    maybe_none = None
    return maybe_none.value  # type: ignore[union-attr]  # Intentional bug corpus sample.


def none_dereference_negative() -> str:
    """Avoid none-dereference by calling a method on a non-None concrete string."""
    text = "safe"
    return text.upper()


def overflow_positive(x: int, y: int) -> int:
    """Trigger overflow by adding unconstrained symbolic integers."""
    return x + y


def overflow_negative() -> int:
    """Avoid overflow by adding small concrete integers."""
    return 1 + 2


class _ResourceHandle:
    """Simple in-memory resource object with close support."""

    def close(self) -> None:
        """Close the synthetic resource."""
        return None


_RESOURCE_HANDLE = _ResourceHandle()


def open(*args: object, **kwargs: object) -> _ResourceHandle:
    """Provide a local open-like callable to exercise resource leak tracking without I/O."""
    return _RESOURCE_HANDLE


def _close_handle_with_nested_control(
    handle: _ResourceHandle, a: int, b: int, c: int, d: int, e: int, f: int
) -> None:
    """Close a handle via nested control flow to emulate realistic cleanup logic."""
    if a > 0:
        if b > 0:
            handle.close()
            return
        if c > 0:
            handle.close()
            return
    else:
        if d > 0 and e <= 0:
            handle.close()
            return
    if f > 0:
        handle.close()
        return
    handle.close()


def resource_leak_positive() -> int:
    """Trigger resource-leak by opening a resource and returning without closing it."""
    handle = open("virtual", "w")
    _ = handle
    return 1


def resource_leak_negative() -> int:
    """Avoid resource-leak by closing the resource before returning."""
    handle = open("virtual", "w")
    handle.close()
    return 1


def resource_leak_path_explosion_positive(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    """Trigger resource leak on a rare early-return path hidden in heavy branching."""
    handle = open("virtual", "w")
    if _rare_path_gate(a, b, c, d, e, f):
        return 1
    _close_handle_with_nested_control(handle, a, b, c, d, e, f)
    return 2


def resource_leak_path_explosion_negative(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    """Avoid resource leak under the same high-path branching profile."""
    handle = open("virtual", "w")
    _close_handle_with_nested_control(handle, a, b, c, d, e, f)
    return 1


def type_error_positive(x: int) -> int:
    """Trigger type-error by using an unsupported arithmetic operator with a string operand."""
    return "left" - x  # type: ignore[operator]  # Intentional bug corpus sample.


def type_error_negative() -> str:
    """Avoid type-error by concatenating two concrete strings."""
    return "left" + "right"


def unbound_variable_positive(x: int) -> int:
    """Trigger unbound-variable by returning a conditionally-defined local."""
    local_value: int
    if x > 0:
        local_value = 1
    return local_value  # type: ignore[reportPossiblyUnboundVariable]  # Intentional corpus bug.


def unbound_variable_negative(x: int) -> int:
    """Avoid unbound-variable by defining the local on all paths."""
    local_value = 1
    return local_value + x


def value_error_positive() -> int:
    """Trigger value-error by converting a concrete invalid string literal to int."""
    return int("not-an-int")


def value_error_negative() -> int:
    """Avoid value-error by converting a valid concrete integer literal."""
    return int("42")


def value_error_range_zero_step_positive(step: int) -> range:
    """Trigger value-error when the symbolic range step is allowed to be zero."""
    return range(0, 10, step)


def value_error_range_nonzero_step_negative() -> range:
    """Avoid value-error by using a concrete nonzero range step."""
    return range(0, 10, 2)


def _build_numeric_token(a: int, b: int, c: int, d: int, e: int, f: int) -> str:
    """Construct a token from deep branching with one rare invalid-literal outcome."""
    if _rare_path_gate(a, b, c, d, e, f):
        return "invalid-token"
    if a + c > b + d:
        return "13"
    if e > f:
        return "21"
    return "34"


def value_error_path_explosion_positive(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    """Trigger value-error from a rare branch hidden inside nested path conditions."""
    return int(_build_numeric_token(a, b, c, d, e, f))


def value_error_path_explosion_negative(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    """Avoid value-error by ensuring every path returns a valid integer token."""
    if _rare_path_gate(a, b, c, d, e, f):
        token = "55"
    elif a + c > b + d:
        token = "89"
    elif e > f:
        token = "144"
    else:
        token = "233"
    return int(token)
