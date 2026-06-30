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

"""Formula traversal helpers shared by detector evidence probes."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


def iter_conjuncts(formula: z3.BoolRef | Iterable[z3.BoolRef]) -> Iterator[z3.BoolRef]:
    """Yield top-level conjuncts from a detector formula or constraint sequence."""
    pending: list[z3.BoolRef] = [formula] if isinstance(formula, z3.BoolRef) else list(formula)
    while pending:
        constraint = pending.pop()
        if z3.is_and(constraint):
            pending.extend(cast("list[z3.BoolRef]", constraint.children()))
            continue
        yield constraint
