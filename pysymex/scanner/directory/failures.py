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

"""Explicit failure results for directory scanner worker failures."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pysymex.scanner.types import ScanResult


def build_failed_scan_result(file_path: Path, exc: Exception) -> ScanResult:
    """Build a result record preserving details of an unexpected scanner failure.

    Args:
        file_path: Path to the target file that failed to scan.
        exc: The exception raised during analysis.

    Returns:
        A :class:`~pysymex.scanner.types.ScanResult` containing the error message.
    """
    return ScanResult(
        file_path=str(file_path),
        timestamp=datetime.now().isoformat(),
        error=f"Scan Error: {type(exc).__name__}({exc})",
    )
