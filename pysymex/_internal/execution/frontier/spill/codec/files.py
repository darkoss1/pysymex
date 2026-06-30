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

"""Spill-file pathing, writing, and cleanup helpers."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.execution.frontier.entries import FrontierQueueEntry
    from pysymex._internal.execution.frontier.spill.values.types import JsonObject


def delete_spilled_frontier_entry(entry: FrontierQueueEntry) -> None:
    """Remove the spill file for ``entry`` when it owns one."""
    spill_file = entry.spilled_checkpoint_path
    if spill_file is not None:
        spill_file.unlink(missing_ok=True)


def spill_path(root: Path, *, state_id: int, capsule_id: str) -> Path:
    """Return the deterministic spill path for one live state ID."""
    root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        msg = "frontier spill root is not a directory"
        raise OSError(msg)
    capsule_hash = sha256(capsule_id.encode("utf-8")).hexdigest()[:16]
    candidate = (root / f"frontier-{state_id}-{capsule_hash}.json").resolve(strict=False)
    if not candidate.is_relative_to(root):
        msg = "frontier spill path escaped configured root"
        raise OSError(msg)
    return candidate


def write_spill_payload(spill_file: Path, payload: JsonObject) -> None:
    """Write one spill payload atomically within the spill directory."""
    temporary_path = spill_file.with_name(f"{spill_file.name}.tmp")
    with temporary_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
    temporary_path.replace(spill_file)
