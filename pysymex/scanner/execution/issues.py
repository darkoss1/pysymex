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

"""Scanner issue conversion for symbolic execution results.

Part of the issue reporting pipeline. Extracts raw issues discovered during
symbolic VM execution and attaches static code metadata (such as class name,
function name, and source file path) before forwarding them to the scanner sink.
"""

from __future__ import annotations

import dataclasses
import types

from pysymex.execution.results.result import ExecutionResult
from pysymex.scanner.issue_sink import ScannerIssueSink


def emit_execution_issues(
    exec_result: ExecutionResult,
    code: types.CodeType,
    class_name: str | None,
    full_path: str | None,
    issue_sink: ScannerIssueSink,
) -> None:
    """Attach code-object context to executor issues and emit them.

    Copies raw issues from the ``ExecutionResult``, fills in class, function,
    and path fields based on the compiled code object context, and forwards them
    to the sink.

    Args:
        exec_result: The VM execution result containing raw issues.
        code: The compiled code object under execution.
        class_name: Enclosing class name, if the code belongs to a method.
        full_path: Absolute path to the source file containing the code.
        issue_sink: The destination sink for scanner issues.

    Side Effects:
        Forwards processed issues to the provided ``issue_sink``.
    """
    for raw_issue in exec_result.issues:
        processed_issue = dataclasses.replace(
            raw_issue,
            function_name=code.co_name,
            class_name=class_name,
            full_path=full_path,
        )
        issue_sink.handle_issue(processed_issue)
