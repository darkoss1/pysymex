"""Shared helpers for stdlib math model tests."""

from __future__ import annotations

from pysymex.core.state.record import VMState


def make_state() -> VMState:
    return VMState()
