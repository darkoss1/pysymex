# pysymex: Python Symbolic Execution & Formal Verification
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

"""Cross-version compatibility helpers for CPython internals."""

from __future__ import annotations

import dis
import sys
from itertools import pairwise as pairwise

if sys.version_info >= (3, 12):
    from itertools import batched as batched
else:
    from collections.abc import Iterable, Iterator
    from itertools import islice
    from typing import TypeVar

    _T = TypeVar("_T")

    def batched(iterable: Iterable[_T], n: int) -> Iterator[tuple[_T, ...]]:
        """Polyfill for itertools.batched (3.12+)."""
        if n < 1:
            raise ValueError("n must be at least one")
        it = iter(iterable)
        while batch := tuple(islice(it, n)):
            yield batch


def get_starts_line(instr: dis.Instruction) -> int | None:
    """Return the starting line number from *instr*, or ``None``.

    ``dis.Instruction.starts_line`` changed type across Python versions
    (``int | None`` in <=3.12, ``bool`` in 3.13+).  This wrapper
    normalises the value so callers always get ``int | None`` without
    needing per-site type-ignore comments.
    """
    sl: object = getattr(instr, "starts_line", None)
    if sl is not None and isinstance(sl, int) and not isinstance(sl, bool):
        return sl
    return None
