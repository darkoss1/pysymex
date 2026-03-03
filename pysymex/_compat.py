"""Cross-version compatibility helpers for CPython internals."""

from __future__ import annotations


import dis


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
