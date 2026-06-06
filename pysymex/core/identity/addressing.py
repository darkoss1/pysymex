# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""Context-bound monotonic identifiers for symbolic expressions.

This module owns the shared counter used in synthetic symbolic names and
symbolic addresses. It is deliberately outside `core.memory` so symbolic value
carriers, memory helpers, execution lowering, and model code can share one
allocator without making identity allocation a memory-store concern.

Notes:
    Distinct counters are isolated only when callers reset or establish them
    in distinct contexts; copying a context can retain the same counter value.
"""

from __future__ import annotations

import contextvars
from typing import Final
import itertools

_DEFAULT_START: Final[int] = 0x1_0000

_counter_var: contextvars.ContextVar[itertools.count[int]] = contextvars.ContextVar(
    "pysymex_identity_counter",
)


def next_address() -> int:
    """Return the next integer from the current context's identity counter."""
    try:
        counter = _counter_var.get()
    except LookupError:
        counter = itertools.count(_DEFAULT_START)
        _counter_var.set(counter)
    return next(counter)
