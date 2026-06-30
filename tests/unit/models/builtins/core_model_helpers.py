from __future__ import annotations

from pysymex._internal.core.state.record import VMState


def state() -> VMState:
    return VMState(pc=0)
