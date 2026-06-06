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

"""Native-isolation-safe spill policy for compact POLAR frontier entries.

Frontier spill is intentionally narrow. The policy may persist only compact
checkpoint entries whose snapshot contains primitive Python roots and optional
SMT2-encoded Z3 constraints, with no arbitrary target-derived object roots.
Unsupported payloads remain resident and produce typed denials instead of
silent lossy serialization.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from pysymex.execution.frontier.entries import FrontierQueueEntry
from pysymex.execution.frontier.spill.codec import (
    checkpoint_spill_payload,
    delete_spilled_frontier_entry,
    spill_path,
    write_spill_payload,
)
from pysymex.execution.frontier.spill.decode import materialize_spilled_frontier_entry

__all__ = [
    "FrontierSpillDecision",
    "FrontierSpillPolicy",
    "FrontierSpillStatus",
    "delete_spilled_frontier_entry",
    "materialize_spilled_frontier_entry",
]


class FrontierSpillStatus(Enum):
    """Typed outcome of a frontier spill request."""

    SPILLED = "spilled"
    DISABLED = "disabled"
    NOT_LIVE = "not_live"
    INVALID_SPILL_ROOT = "invalid_spill_root"
    UNSUPPORTED_PAYLOAD = "unsupported_payload"
    WRITE_FAILED = "write_failed"


@dataclass(frozen=True, slots=True)
class FrontierSpillDecision:
    """Result of evaluating whether a frontier entry may be spilled."""

    status: FrontierSpillStatus
    explanation: str
    spilled_entry: FrontierQueueEntry | None = None
    spill_path: Path | None = None

    @property
    def can_spill(self) -> bool:
        """Return whether the entry may be moved out of resident memory."""
        return (
            self.status is FrontierSpillStatus.SPILLED
            and self.spilled_entry is not None
            and self.spill_path is not None
        )


@dataclass(frozen=True, slots=True)
class FrontierSpillPolicy:
    """Filesystem spill policy for compact, primitive frontier checkpoints.

    Filesystem spill is disabled by default. When enabled, callers must provide
    an explicit spill directory. The policy writes deterministic JSON only for
    checkpoint snapshots that are safe to reconstruct without pickle, imports,
    code execution, or arbitrary object resurrection. Solver constraints cross
    this boundary only as deterministic SMT2 and are digest-checked after
    parsing.
    """

    filesystem_spill_enabled: bool = False
    spill_directory: Path | None = None

    def evaluate(
        self,
        entry: FrontierQueueEntry,
        *,
        state_id: int,
    ) -> FrontierSpillDecision:
        """Return the spill decision for ``entry`` and write safe payloads."""
        if not self.filesystem_spill_enabled:
            return FrontierSpillDecision(
                status=FrontierSpillStatus.DISABLED,
                explanation="frontier filesystem spill is disabled",
            )
        if entry.is_spilled:
            return FrontierSpillDecision(
                status=FrontierSpillStatus.UNSUPPORTED_PAYLOAD,
                explanation="frontier entry is already spilled",
            )
        if entry.checkpoint is None:
            return FrontierSpillDecision(
                status=FrontierSpillStatus.UNSUPPORTED_PAYLOAD,
                explanation="frontier spill only supports compact checkpoint entries",
            )

        root = self._resolved_spill_root()
        if root is None:
            return FrontierSpillDecision(
                status=FrontierSpillStatus.INVALID_SPILL_ROOT,
                explanation="frontier filesystem spill requires an explicit directory",
            )

        payload = checkpoint_spill_payload(entry.checkpoint)
        if payload is None:
            return FrontierSpillDecision(
                status=FrontierSpillStatus.UNSUPPORTED_PAYLOAD,
                explanation=(
                    "frontier checkpoint contains non-primitive target-derived roots or "
                    "unsupported solver payloads"
                ),
            )

        try:
            target_path = spill_path(
                root,
                state_id=state_id,
                capsule_id=entry.checkpoint.capsule.capsule_id,
            )
            write_spill_payload(target_path, payload)
        except OSError as exc:
            return FrontierSpillDecision(
                status=FrontierSpillStatus.WRITE_FAILED,
                explanation=f"frontier spill write failed: {type(exc).__name__}",
            )

        spilled_entry = FrontierQueueEntry(spilled_checkpoint_path=target_path)
        return FrontierSpillDecision(
            status=FrontierSpillStatus.SPILLED,
            explanation="frontier checkpoint spilled to filesystem",
            spilled_entry=spilled_entry,
            spill_path=target_path,
        )

    def evaluate_missing(self) -> FrontierSpillDecision:
        """Return the spill decision for a stale or missing frontier entry."""
        return FrontierSpillDecision(
            status=FrontierSpillStatus.NOT_LIVE,
            explanation="frontier entry is not live",
        )

    def _resolved_spill_root(self) -> Path | None:
        """Return a normalized spill root when one is configured."""
        if self.spill_directory is None:
            return None
        return self.spill_directory.resolve(strict=False)
