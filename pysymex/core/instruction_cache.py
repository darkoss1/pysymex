"""Shared instruction cache for ``dis.get_instructions``.

Calling ``dis.get_instructions()`` on the same code object repeatedly is a
surprisingly expensive operation (~14 µs per call on CPython 3.13) because it
walks the bytecode and builds ``Instruction`` namedtuples from scratch every
time.

During a symbolic-execution run, the same code object may be disassembled by
the executor, the loop detector, the state merger, the abstract interpreter,
the CFG builder, and cross-function analysis — easily 6+ times per function.

This module provides a single process-wide cache keyed on the *code object
itself* (not ``id(code)``).  Using the object as key prevents stale-id
collisions that occur when code objects are GC'd and a new object gets
allocated at the same address.  The dict also keeps a strong reference to
each cached code object, which is acceptable given the 2048-entry limit.
"""

from __future__ import annotations


import dis

import types

_CACHE: dict[types.CodeType, list[dis.Instruction]] = {}

_MAX_CACHE = 2048


def get_instructions(code: types.CodeType) -> list[dis.Instruction]:
    """Return a **cached** list of instructions for *code*.

    The returned list **must not be mutated** — it is shared across callers.
    If you need a mutable copy, do ``list(get_instructions(code))``.
    """

    cached = _CACHE.get(code)

    if cached is not None:
        return cached

    instructions = list(dis.get_instructions(code))

    if len(_CACHE) >= _MAX_CACHE:
        keys = list(_CACHE.keys())

        for k in keys[: _MAX_CACHE // 4]:
            del _CACHE[k]

    _CACHE[code] = instructions

    return instructions


def clear_cache() -> None:
    """Clear the instruction cache.  Call between analysis units if needed."""

    _CACHE.clear()
