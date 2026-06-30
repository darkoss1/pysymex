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

"""Pure aggregate counters for symbolic scan results.

This module owns reusable summary data derived from scanner results. Console
presentation belongs to CLI reporters, while scanner modules remain responsible
only for producing ``ScanResult`` records.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.scanner.types import ScanResult


@dataclass(frozen=True)
class ScanResultsSummary:
    """Aggregate counters for a directory scan result set."""

    total_issues: int
    files_with_issues: int
    errors: int
    degraded: int
    missing_files: int


def summarize_scan_results(
    results: Sequence[ScanResult],
    total_files: int,
) -> ScanResultsSummary:
    """Compute presentation counters for completed scan results."""
    return ScanResultsSummary(
        total_issues=sum(len(result.issues) for result in results),
        files_with_issues=sum(1 for result in results if result.issues),
        errors=sum(1 for result in results if result.error),
        degraded=sum(1 for result in results if result.degraded_passes),
        missing_files=max(0, total_files - len(results)),
    )
