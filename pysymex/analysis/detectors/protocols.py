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

"""Detector-facing protocols for execution and scanner boundary consumers."""

from __future__ import annotations

import dis
from collections.abc import Callable
from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol as TypingProtocol, runtime_checkable

if TYPE_CHECKING:
    from pysymex.typing import SolverProtocol


__all__ = [
    "ExecutionContextLike",
    "ScanReporter",
]


@runtime_checkable
class ExecutionContextLike(TypingProtocol):
    """Read-side executor contract consumed by detector-facing helpers.

    Analysis owns this structural view so detector modules do not import the
    execution runtime package. The concrete executor remains an execution
    object that satisfies this protocol structurally.
    """

    instructions: Sequence[dis.Instruction]
    solver: SolverProtocol
    _paths_explored: int
    _coverage: set[int]
    issues: Sequence[object]

    def register_hook(self, hook_name: str, handler: Callable[..., object]) -> None:
        """Register an execution lifecycle callback."""
        ...


class ScanReporter(TypingProtocol):
    """Protocol for scanner reporting sinks used by scanner execution."""

    def on_status(self, message: str) -> None:
        """Handle a status message update from the scan.

        Args:
            message: The status description text.
        """
        ...

    def on_issue(self, issue: dict[str, object]) -> None:
        """Handle a detected issue from the scan.

        Args:
            issue: Dictionary representing the details of the detected issue.
        """
        ...

    def on_error(self, file_path: object, error: str) -> None:
        """Handle an error encountered during the scan of a file.

        Args:
            file_path: Path of the file that caused the error.
            error: The error message details.
        """
        ...

    def on_progress(
        self, completed: int, total: int, file_path: object, result: object | None
    ) -> None:
        """Report scan progress.

        Args:
            completed: Number of files successfully processed.
            total: Total number of files to process.
            file_path: The file path currently being processed.
            result: The result of processing the current file, if any.
        """
        ...

    def on_summary(self, results: Sequence[object], total_files: int) -> None:
        """Handle the final summary reporting at the completion of a scan.

        Args:
            results: A sequence of all results gathered during the scan.
            total_files: The total number of files scanned.
        """
        ...
