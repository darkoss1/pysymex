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

"""Policy for skipping known-benign exception handler patterns."""

from __future__ import annotations

from pysymex.analysis.domains.exceptions.handler.context import ExceptionHandlerInfo


def should_skip_issue_in_handler(
    line_number: int | None,
    issue_kind: str,
    handlers: list[ExceptionHandlerInfo],
) -> bool:
    """Determine if an issue should be skipped because it's in an expected handler.

    Args:
        line_number: Line number of the issue
        issue_kind: Kind of issue (e.g., "UNREACHABLE_CODE")
        handlers: List of exception handlers

    Returns:
        True if the issue should be skipped
    """
    if line_number is None:
        return False

    skip_in_handler = {
        "UNREACHABLE_CODE",
        "DEAD_CODE",
    }

    if issue_kind not in skip_in_handler:
        return False

    for handler in handlers:
        if handler.start_pc <= line_number <= handler.end_pc:
            return True

    return False
