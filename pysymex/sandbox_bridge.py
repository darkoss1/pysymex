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

"""Backward-compatibility shim — use ``pysymex.sandbox.bridge`` instead.

.. deprecated::
    This module has been moved to ``pysymex.sandbox.bridge``.
    All public names are re-exported here for backward compatibility.
"""

from __future__ import annotations


from pysymex.sandbox.bridge import (
    BytecodeBlob,
    ConcreteResult,
    execute_concrete,
    extract_bytecode,
)

__all__ = [
    "BytecodeBlob",
    "ConcreteResult",
    "execute_concrete",
    "extract_bytecode",
]
