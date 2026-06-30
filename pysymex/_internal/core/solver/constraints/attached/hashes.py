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

"""Expression-local structural hash reuse for Z3 wrappers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Callable

    import z3

Z3_HASH_ATTR: Final = "_symex_hash"


def attached_hash(constraint: z3.ExprRef) -> int | None:
    """Return the expression-local cached hash when present."""
    cached = getattr(constraint, Z3_HASH_ATTR, None)
    return cached if isinstance(cached, int) else None


def try_attach_hash(constraint: z3.ExprRef, computed: int) -> bool:
    """Attach *computed* to a Z3 wrapper and report whether it succeeded."""
    try:
        setattr(constraint, Z3_HASH_ATTR, computed)
    except AttributeError:
        return False
    return True


def combined_attached_hash(
    constraints: list[z3.BoolRef] | list[z3.ExprRef],
    *,
    compute_hash: Callable[[z3.ExprRef], int],
) -> int:
    """Return an ordered tuple hash using expression-local hash caches."""
    if not constraints:
        return 0

    hashes: list[int] = []
    append_hash = hashes.append
    hash_attr = Z3_HASH_ATTR
    for constraint in constraints:
        cached: int | None = getattr(constraint, hash_attr, None)
        if cached is not None:
            append_hash(cached)
        else:
            append_hash(compute_hash(constraint))
    return hash(tuple(hashes))


def combined_attached_sorted_hash(
    constraints: list[z3.BoolRef] | list[z3.ExprRef],
    *,
    compute_hash: Callable[[z3.ExprRef], int],
) -> int:
    """Return an order-independent tuple hash using expression-local caches."""
    if not constraints:
        return 0

    hashes: list[int] = []
    append_hash = hashes.append
    hash_attr = Z3_HASH_ATTR
    for constraint in constraints:
        cached: int | None = getattr(constraint, hash_attr, None)
        if cached is not None:
            append_hash(cached)
        else:
            append_hash(compute_hash(constraint))
    hashes.sort()
    return hash(tuple(hashes))
