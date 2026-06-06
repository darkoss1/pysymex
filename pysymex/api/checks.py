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

"""Public issue-checking convenience helpers."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.execution.results.result import ExecutionResult


def quick_check(
    analyze_func: Callable[..., ExecutionResult],
    func: Callable[..., object],
) -> list[Issue]:
    """Quick-check a function for common issues."""
    result = analyze_func(func, max_paths=100, max_iterations=500)
    return result.issues


def check_division_by_zero(
    analyze_func: Callable[..., ExecutionResult],
    func: Callable[..., object],
) -> list[Issue]:
    """Check specifically for division-by-zero issues."""
    result = analyze_func(
        func,
        detect_division_by_zero=True,
        detect_assertion_errors=False,
        detect_index_errors=False,
        detect_type_errors=False,
    )
    deduped: dict[tuple[int | None, int | None, tuple[tuple[str, object], ...]], Issue] = {}
    for issue in result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO):
        counterexample = issue.get_counterexample() or {}
        key = (
            issue.pc,
            issue.line_number,
            tuple(sorted(counterexample.items())),
        )
        deduped.setdefault(key, issue)
    return list(deduped.values())


def check_assertions(
    analyze_func: Callable[..., ExecutionResult],
    func: Callable[..., object],
) -> list[Issue]:
    """Check specifically for assertion errors."""
    result = analyze_func(
        func,
        detect_division_by_zero=False,
        detect_assertion_errors=True,
        detect_index_errors=False,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.ASSERTION_ERROR)


def check_index_errors(
    analyze_func: Callable[..., ExecutionResult],
    func: Callable[..., object],
) -> list[Issue]:
    """Check specifically for index-out-of-bounds errors."""
    result = analyze_func(
        func,
        detect_division_by_zero=False,
        detect_assertion_errors=False,
        detect_index_errors=True,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.INDEX_ERROR)


def format_issues(
    issues: Sequence[Issue],
    format_type: str = "text",
) -> str:
    """Format a list of issues for display."""
    if format_type == "json":
        import json

        return json.dumps([issue.to_dict() for issue in issues], indent=2)

    lines: list[str] = []
    for i, issue in enumerate(issues, 1):
        lines.append(f"[{i}] {issue.format()}")
    return "\n\n".join(lines)
