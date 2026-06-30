import dis
from collections.abc import Callable
from typing import cast

from pysymex._internal.core.cache.code.exceptions import get_exception_entries
from pysymex._internal.core.cache.code.exceptions import (
    get_exception_entries as direct_get_exception_entries,
)
from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.cache.code.instructions import (
    get_instructions as direct_get_instructions,
)


def test_code_object_cache_exports_use_direct_owners() -> None:
    assert get_instructions is direct_get_instructions
    assert get_exception_entries is direct_get_exception_entries


def test_get_instructions() -> None:
    """Scenario: identical code object lookup twice; expected same cached tuple object."""
    get_instructions.cache_clear()

    def sample() -> int:
        return 1

    first = get_instructions(sample.__code__)
    second = get_instructions(sample.__code__)
    assert first is second


def test_get_instructions_resolves_kw_names_constants() -> None:
    """Scenario: CPython 3.11 KW_NAMES argval gap; expected concrete name tuple."""
    get_instructions.cache_clear()

    def sample(func: Callable[..., object]) -> object:
        return func(value=1)

    kw_names = [
        instruction
        for instruction in get_instructions(sample.__code__)
        if instruction.opname == "KW_NAMES"
    ]
    if not kw_names:
        return

    assert kw_names[0].argval == ("value",)


def test_get_exception_entries_caches_code_metadata() -> None:
    """Scenario: exception table lookup twice; expected same cached tuple object."""
    get_exception_entries.cache_clear()

    def sample(value: int) -> int:
        try:
            return 10 // value
        except ZeroDivisionError:
            return 0

    raw_entries: object = getattr(dis.Bytecode(sample.__code__), "exception_entries", ())
    assert isinstance(raw_entries, list)
    expected_entries: tuple[object, ...] = tuple(cast("list[object]", raw_entries))
    first = get_exception_entries(sample.__code__)
    second = get_exception_entries(sample.__code__)

    assert first
    assert first == expected_entries
    assert first is second


def test_get_exception_entries_returns_empty_tuple_without_exception_table() -> None:
    """Scenario: straight-line function; expected cached empty exception metadata."""
    get_exception_entries.cache_clear()

    def sample() -> int:
        return 1

    first = get_exception_entries(sample.__code__)
    second = get_exception_entries(sample.__code__)

    assert first == ()
    assert first is second
