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

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pysymex.core.state import VMState


@runtime_checkable
class HasName(Protocol):
    @property
    def name(self) -> str:
        """Return an identifier-like display name."""
        return ""


def get_named_value_name(value: object) -> str | None:
    """Return ``value.name`` only when statically and dynamically safe."""
    if isinstance(value, HasName):
        return value.name
    return None


def resolve_target_name(state: VMState, argc: int) -> str | None:
    """Resolve target name."""
    candidate_indices = [len(state.stack) - argc - 1, len(state.stack) - argc - 2]
    for index in candidate_indices:
        if index < 0 or index >= len(state.stack):
            continue
        candidate = state.stack[index]
        for attr in ("qualname", "name", "origin"):
            value = getattr(candidate, attr, None)
            if isinstance(value, str) and value:
                return value
    return None
