"""Reproduction for Issue #123: Memory Aliasing False Positive.

This test ensures that forked states maintain absolute memory isolation
when modifying symbolic collections.
"""

from __future__ import annotations

from pysymex.core.state.record import VMState


def test_issue_123_aliasing_on_fork() -> None:
    """Regression test for Issue #123.

    In v0.3.2, modifying a list in a child state accidentally updated the
    parent state due to a shallow copy bug in the memory model.
    """
    state = VMState(memory={7: "parent"})
    child = state.fork()
    child.memory[7] = "child"
    assert state.memory[7] == "parent"
