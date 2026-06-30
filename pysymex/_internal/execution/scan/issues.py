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

"""Issue emission helpers for source scan execution passes."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import types

    from pysymex._internal.execution.results.result import ExecutionResult
    from pysymex._internal.execution.scan.types import ScanIssueSink


def emit_execution_issues(
    exec_result: ExecutionResult,
    code: types.CodeType,
    class_name: str | None,
    full_path: str | None,
    issue_sink: ScanIssueSink,
) -> None:
    """Attach code-object context to executor issues and emit them."""
    for raw_issue in exec_result.issues:
        has_issue_function_context = raw_issue.function_name is not None
        function_name = raw_issue.function_name or code.co_name
        resolved_class_name = (
            raw_issue.class_name if raw_issue.class_name is not None else class_name
        )
        processed_issue = dataclasses.replace(
            raw_issue,
            function_name=function_name,
            class_name=resolved_class_name,
            full_path=raw_issue.full_path
            or _context_full_path(
                function_name,
                resolved_class_name,
                full_path,
                has_issue_function_context=has_issue_function_context,
            ),
        )
        issue_sink.handle_issue(processed_issue)


def _context_full_path(
    function_name: str,
    class_name: str | None,
    fallback_full_path: str | None,
    *,
    has_issue_function_context: bool,
) -> str | None:
    """Return precise issue path when the issue context differs from scan target context."""
    if not has_issue_function_context:
        return fallback_full_path
    if fallback_full_path is None:
        return f"{class_name}.{function_name}" if class_name is not None else function_name
    if fallback_full_path.endswith(function_name):
        return fallback_full_path
    return f"{class_name}.{function_name}" if class_name is not None else function_name
