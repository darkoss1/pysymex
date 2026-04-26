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

"""
pysymex Collection Theories - Phase 15
Provides precise symbolic modeling for Python's built-in collections
with full operation semantics. Uses Z3 theories for verification.

Collections:
- SymbolicListOps: List operations (append, extend, pop, etc.)
- SymbolicDictOps: Dict operations (get, set, update, etc.)
- SymbolicSetOps: Set operations (add, union, intersection, etc.)
- SymbolicTupleOps: Tuple operations (indexing, slicing, etc.)
- SymbolicStringOps: String operations (contains, startswith, etc.)

Each operation is modeled to produce:
1. The result value (possibly symbolic)
2. Constraints that must hold for the operation
3. The mutated collection (for mutable types)

Implementation split across submodules:
- collections_list: OpResult, SymbolicListOps, SymbolicStringOps
- collections_mapping: SymbolicDictOps, SymbolicSetOps, SymbolicTupleOps
"""

from __future__ import annotations

from pysymex.core.memory.collections.lists import (
    OpResult,
    SymbolicListOps,
    SymbolicStringOps,
)
from pysymex.core.memory.collections.mappings import (
    SymbolicDictOps,
    SymbolicSetOps,
    SymbolicTupleOps,
)

__all__ = [
    "OpResult",
    "SymbolicDictOps",
    "SymbolicListOps",
    "SymbolicSetOps",
    "SymbolicStringOps",
    "SymbolicTupleOps",
]
