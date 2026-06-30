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

"""Scanner-owned callback protocols.

The scanner owns scan lifecycle events and exposes them as structural
protocols. CLI code may implement these protocols for terminal presentation,
but detector and execution packages should not own scan progress callbacks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence


@runtime_checkable
class ScanReporter(Protocol):
    """Protocol for scanner lifecycle reporting sinks."""

    def on_status(self, message: str) -> None:
        """Handle a status message update from the scan."""
        ...

    def on_issue(self, issue: dict[str, object]) -> None:
        """Handle a detected issue from the scan."""
        ...

    def on_error(self, file_path: object, error: str) -> None:
        """Handle an error encountered during the scan of a file."""
        ...

    def on_progress(
        self,
        completed: int,
        total: int,
        file_path: object,
        result: object | None,
    ) -> None:
        """Report scan progress."""
        ...

    def on_summary(self, results: Sequence[object], total_files: int) -> None:
        """Handle final summary reporting at scan completion."""
        ...
