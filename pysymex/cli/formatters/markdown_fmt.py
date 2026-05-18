"""Markdown formatter for scan results."""

from __future__ import annotations

from typing import Any, Mapping, Sequence, cast

from pysymex.cli.formatters.base import Formatter, verify_result_to_dict
from pysymex.config import VERSION


class MarkdownFormatter(Formatter):
    """Outputs scan results as a Markdown report."""

    def format_static(
        self,
        issues: Sequence[Any],
        total: int,
        suppressed: int,
        duration: float,
    ) -> str:
        lines = [
            "# pysymex static analysis report",
            "",
            f"- **Issues:** {total}",
            f"- **Suppressed:** {suppressed}",
            f"- **Duration:** {duration:.2f}s",
            f"- **Version:** {VERSION}",
            "",
            "## Issues",
            "",
        ]
        if total == 0:
            lines.append("No issues found.")
        else:
            for issue in issues:
                severity = str(getattr(issue, "severity", "warning")).upper()
                kind = str(getattr(issue, "kind", "UNKNOWN"))
                file = str(getattr(issue, "file", "unknown"))
                line = getattr(issue, "line", "?")
                message = str(getattr(issue, "message", ""))
                lines.append(f"### [{severity}] {kind}")
                lines.append(f"- **Location:** `{file}:{line}`")
                lines.append(f"- **Message:** {message}")
                suggestion = getattr(issue, "suggestion", None)
                if suggestion:
                    lines.append(f"- **Suggestion:** {suggestion}")
                lines.append("")
        return "\n".join(lines)

    def format_pipeline(
        self,
        results: Mapping[str, Any],
        all_issues: list[tuple[str, Any]],
        total: int,
        duration: float,
    ) -> str:
        lines = [
            "# pysymex pipeline scan report",
            "",
            f"- **Files Scanned:** {len(results)}",
            f"- **Total Issues:** {total}",
            f"- **Duration:** {duration:.2f}s",
            f"- **Version:** {VERSION}",
            "",
            "## Issues",
            "",
        ]
        if total == 0:
            lines.append("No issues found.")
        else:
            for file_path, issue in all_issues:
                severity = str(getattr(issue, "severity", "warning")).upper()
                kind = str(getattr(issue, "kind", "UNKNOWN"))
                line = getattr(issue, "line", "?")
                message = str(getattr(issue, "message", ""))
                lines.append(f"### [{severity}] {kind}")
                lines.append(f"- **Location:** `{file_path}:{line}`")
                lines.append(f"- **Message:** {message}")
                lines.append("")
        return "\n".join(lines)

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        lines = [
            "# pysymex symbolic execution report",
            "",
            f"- **Files Scanned:** {len(results)}",
            f"- **Issues Found:** {total}",
            f"- **Duration:** {duration:.2f}s",
            f"- **Version:** {VERSION}",
            "",
            "## Issues",
            "",
        ]
        if total == 0:
            lines.append("No issues found.")
        else:
            for scan_result in results:
                if not hasattr(scan_result, "issues") or not scan_result.issues:
                    continue
                file_path = getattr(scan_result, "file_path", "unknown")
                lines.append(f"## File: `{file_path}`")
                lines.append("")
                for issue in scan_result.issues:
                    if not isinstance(issue, dict):
                        continue
                    issue_dict = cast("dict[str, object]", issue)
                    kind = str(issue_dict.get("kind", "UNKNOWN"))
                    line = issue_dict.get("line", "?")
                    message = str(issue_dict.get("message", ""))
                    lines.append(f"### {kind}")
                    lines.append(f"- **Location:** `{file_path}:{line}`")
                    lines.append(f"- **Message:** {message}")
                    ce = issue_dict.get("counterexample")
                    if isinstance(ce, dict):
                        lines.append("- **Triggering Inputః")
                        lines.append("  ```python")
                        for k, v in cast("dict[object, object]", ce).items():
                            lines.append(f"  {k} = {repr(v)}")
                        lines.append("  ```")
                    lines.append("")
        return "\n".join(lines)

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        lines = [
            "# pysymex contract verification report",
            "",
            f"- **Functions Verified:** {len(results)}",
            f"- **Findings:** {total}",
            f"- **Duration:** {duration:.2f}s",
            f"- **Version:** {VERSION}",
            "",
        ]
        if not results:
            lines.append("No contracted functions were verified.")
            return "\n".join(lines)
        if total == 0:
            lines.append("All selected contracts verified.")
            return "\n".join(lines)

        lines.append("## Findings")
        lines.append("")
        for result in results:
            data = verify_result_to_dict(result)
            if data["total_issues"] == 0:
                continue
            lines.append(f"### `{data['function_name']}`")
            lines.append("")
            lines.append(
                f"- **Paths:** {data['paths_explored']} explored, "
                f"{data['paths_completed']} completed"
            )
            for section, heading in (
                ("runtime_issues", "Runtime Issues"),
                ("contract_issues", "Contract Issues"),
                ("arithmetic_issues", "Arithmetic Issues"),
            ):
                issues = data[section]
                if isinstance(issues, list) and issues:
                    lines.append(f"- **{heading}:**")
                    lines.extend(f"  - {issue}" for issue in cast("list[object]", issues))
            lines.append("")
        return "\n".join(lines)
