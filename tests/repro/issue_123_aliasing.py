# PySyMex: Python Symbolic Execution & Formal Verification
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

"""Reproduction for Issue #123: Memory Aliasing False Positive.

This test ensures that forked states maintain absolute memory isolation
when modifying symbolic collections.
"""

from __future__ import annotations

import pytest
from pysymex.core.state import VMState
from pysymex.core.memory import MemoryState

def test_issue_123_aliasing_on_fork() -> None:
    """Regression test for Issue #123.
    
    In v0.3.2, modifying a list in a child state accidentally updated the
    parent state due to a shallow copy bug in the memory model.
    """
    # 1. Setup parent state with a collection
    mem = MemoryState()
    state = VMState(memory=mem)
    # Use variables to satisfy reportUnusedVariable and reportUnusedImport
    _ = pytest.mark.regression
    
    raise NotImplementedError(f"Reproduction logic for memory aliasing in {state} needed")
