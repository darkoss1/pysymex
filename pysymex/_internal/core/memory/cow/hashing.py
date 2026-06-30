# pysymex: python symbolic execution & formal verification
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

"""Structural hash summaries for copy-on-write collection wrappers.

These helpers produce compact state summaries for diagnostics and cache keys.
They are not semantic equality proofs.
"""

from __future__ import annotations

from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)


def cow_pair_hash(key: object, value: object) -> int:
    """Return a mixed structural summary for one mapping item."""
    key_hash = _safe_hash(key)
    value_hash = _safe_hash(value)
    pair_hash = (key_hash ^ (value_hash * 1000003)) & 0xFFFFFFFFFFFFFFFF
    pair_hash = (pair_hash ^ (pair_hash >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
    pair_hash = (pair_hash ^ (pair_hash >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
    return pair_hash ^ (pair_hash >> 31)


def cow_set_item_hash(item: object) -> int:
    """Return a mixed structural summary for one set member."""
    item_hash = hash(item) & 0xFFFFFFFFFFFFFFFF
    item_hash = (item_hash ^ (item_hash >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
    item_hash = (item_hash ^ (item_hash >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
    return item_hash ^ (item_hash >> 31)


def deterministic_sort_key(value: object) -> tuple[str, str, str]:
    """Return a stable cross-type sort key for diagnostic snapshots."""
    value_type = type(value)
    return (value_type.__module__, value_type.__qualname__, repr(value))


def _safe_hash(obj: object) -> int:
    """Derive a hash summary from a value or its symbolic representation."""
    try:
        return hash(obj)
    except TypeError:
        if logger.state.debug_enabled:
            logger.debug("Hashing unhashable COW value structurally", exc_info=True)
        hash_value = getattr(obj, "hash_value", None)
        if callable(hash_value):
            hv = hash_value()
            if isinstance(hv, int):
                return hv
            return hash(str(hv))
        to_z3 = getattr(obj, "to_z3", None)
        if callable(to_z3):
            z3_ast = to_z3()
            z3_hash = getattr(z3_ast, "hash", None)
            if callable(z3_hash):
                zh = z3_hash()
                if isinstance(zh, int):
                    return zh
                return hash(str(zh))
            return hash(str(z3_ast))
        return hash(repr(obj))
