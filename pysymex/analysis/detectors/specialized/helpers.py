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

"""Helpers for specialized detectors.

Provides utility functions for name resolution and display representation in specialized detectors.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.analysis.detectors.calls import resolve_call_target_name

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


def get_named_value_name(value: object) -> str | None:
    """Return ``value.name`` only when it is a real display-name string."""
    try:
        name = getattr(value, "name", None)
    except Exception:
        return None
    if isinstance(name, str) and name:
        return name
    return None


def resolve_target_name(state: VMState, argc: int) -> str | None:
    """Resolve target name."""
    return resolve_call_target_name(state, argc, prefer_pre_null=False)
