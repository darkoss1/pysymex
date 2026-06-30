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

"""Snapshot records for live frontier storage diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.obligations.types import FrontierTelemetry


@dataclass(frozen=True, slots=True)
class FrontierWorkStoreStats:
    """Snapshot of live frontier storage and POLAR telemetry counters."""

    enabled: bool
    compact_queueing_enabled: bool
    checkpoint_count: int
    compacted_entry_count: int
    spilled_entry_count: int
    capsule_digest_mismatch_count: int
    reconstruction_mismatch_count: int
    compaction_denied_count: int
    spill_denied_count: int
    telemetry: FrontierTelemetry
