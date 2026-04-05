# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Deterministic address allocation for symbolic execution.

Replaces nondeterministic ``id()`` with a per-session monotonic counter
so that Z3 constraints produce reproducible results across runs.

Session isolation is achieved via :class:`contextvars.ContextVar`:
each ``asyncio.Task`` or explicit ``contextvars.copy_context().run(...)``
gets its own counter, eliminating interleaving between concurrent analyses.

Usage::

    from pysymex.core.addressing import next_address

    addr = next_address()          # monotonic int, safe for Z3 IntVal
    name = f"sym_{next_address()}" # unique Z3 variable name
"""

from __future__ import annotations

import contextvars
import itertools
from typing import Final

_DEFAULT_START: Final[int] = 0x1_0000

_counter_var: contextvars.ContextVar[itertools.count[int]] = contextvars.ContextVar(
    "pysymex_address_counter",
)


def next_address() -> int:
    """Return the next deterministic symbolic address.

    Thread-safe monotonic counter that replaces ``id()`` for both Z3
    addresses (Category A) and Z3 variable-name uniquifiers (Category B).

    When called inside a copied context (``copy_context().run(...)``),
    returns values from a session-private counter.
    """
    try:
        counter = _counter_var.get()
    except LookupError:
        counter = itertools.count(_DEFAULT_START)
        _counter_var.set(counter)
    return next(counter)


def reset(start: int = _DEFAULT_START) -> None:
    """Reset the counter for the current context.

    Useful for testing reproducibility.  Each context (session) can
    be reset independently.
    """
    _counter_var.set(itertools.count(start))
