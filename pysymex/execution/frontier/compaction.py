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

"""In-memory compaction decisions for resident POLAR frontier entries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pysymex.execution.frontier.entries import FrontierQueueEntry

__all__ = [
    "FrontierCompactionDecision",
    "FrontierCompactionStatus",
]


class FrontierCompactionStatus(Enum):
    """Typed outcome of compacting one live frontier entry."""

    COMPACTED = "compacted"
    ALREADY_COMPACT = "already_compact"
    NOT_LIVE = "not_live"
    CHECKPOINT_UNAVAILABLE = "checkpoint_unavailable"


@dataclass(frozen=True, slots=True)
class FrontierCompactionDecision:
    """Result of replacing a resident entry with an exact checkpoint payload."""

    status: FrontierCompactionStatus
    explanation: str
    compacted_entry: FrontierQueueEntry | None = None

    @property
    def can_compact(self) -> bool:
        """Return whether the entry can be replaced by ``compacted_entry``."""
        return (
            self.status is FrontierCompactionStatus.COMPACTED and self.compacted_entry is not None
        )
