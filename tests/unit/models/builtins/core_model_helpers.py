from __future__ import annotations

from pysymex.core.state.record import VMState


def state() -> VMState:
    return VMState(pc=0)
