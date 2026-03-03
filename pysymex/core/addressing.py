"""Deterministic address allocation for symbolic execution.

Replaces nondeterministic ``id()`` with a thread-safe monotonic counter
so that Z3 constraints produce reproducible results across runs.

Usage::
    from pysymex.core.addressing import next_address

    addr = next_address()          # monotonic int, safe for Z3 IntVal
    name = f"sym_{next_address()}" # unique Z3 variable name
"""

from __future__ import annotations


import threading

from typing import Final

_DEFAULT_START: Final[int] = 0x1_0000


_lock = threading.Lock()

_counter: int = _DEFAULT_START


def next_address() -> int:
    """Return the next deterministic symbolic address.

    Thread-safe monotonic counter that replaces ``id()`` for both Z3
    addresses (Category A) and Z3 variable-name uniquifiers (Category B).
    """

    global _counter

    with _lock:
        addr = _counter

        _counter += 1

    return addr


def reset(start: int = _DEFAULT_START) -> None:
    """Reset the counter — useful for testing reproducibility."""

    global _counter

    with _lock:
        _counter = start
