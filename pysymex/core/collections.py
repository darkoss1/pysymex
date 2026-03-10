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

from pysymex.core.collections_list import (
    OpResult,
    SymbolicListOps,
    SymbolicStringOps,
)
from pysymex.core.collections_mapping import (
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
