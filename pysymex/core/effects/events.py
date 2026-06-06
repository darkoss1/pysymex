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

"""Typed write-event facts emitted by VM mutation sites."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class WriteKind(Enum):
    """Modeled write categories visible to effect-sensitive analyses."""

    ATTRIBUTE = "attribute"
    CLOSURE = "closure"
    GLOBAL = "global"
    HEAP = "heap"
    ITEM = "item"
    EXTERNAL = "external"


@dataclass(frozen=True, slots=True)
class WriteEvent:
    """One modeled write observed on a symbolic execution path."""

    kind: WriteKind
    location: str
    pc: int | None
    precise: bool
    source: str


__all__ = ["WriteEvent", "WriteKind"]
