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
    from typing import Any as _Any

    def batched(iterable: Iterable[_Any], n: int) -> Iterator[tuple[_Any, ...]]:
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
