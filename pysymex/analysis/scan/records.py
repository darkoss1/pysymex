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

"""Shared issue record shape for analysis and scan reporting."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypeAlias
from typing import cast

IssueRecord: TypeAlias = dict[str, object]


def normalize_trigger_input(value: object) -> dict[str, object] | None:
    """Return reportable trigger assignments, or ``None`` when none exist."""
    if not isinstance(value, Mapping):
        return None

    mapping = cast("Mapping[object, object]", value)
    if not mapping:
        return None

    return {str(name): assignment for name, assignment in mapping.items()}


def iter_trigger_assignments(value: object) -> tuple[tuple[str, object], ...]:
    """Return deterministic trigger assignments for text formatting."""
    trigger_input = normalize_trigger_input(value)
    if trigger_input is None:
        return ()
    return tuple(sorted(trigger_input.items()))


__all__ = ["IssueRecord", "iter_trigger_assignments", "normalize_trigger_input"]
