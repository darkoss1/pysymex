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

"""Public report rendering helpers."""

from __future__ import annotations

import html
from json import dumps
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypeAlias, cast

from pysymex._internal.api.results import clean, count, data, degraded

if TYPE_CHECKING:
    from pysymex._internal.execution.executors.verified.types import VerifiedExecutionResult
    from pysymex._internal.execution.results.result import ExecutionResult
    from pysymex._internal.reporting.sarif.types.log import SARIFLog
    from pysymex._internal.scanner.types import ScanResult
    from pysymex._internal.api.issues import IssueLike

    ReportValue: TypeAlias = (
        ExecutionResult
        | VerifiedExecutionResult
        | ScanResult
        | Sequence[ScanResult]
        | Sequence[IssueLike]
    )
else:
    ReportValue: TypeAlias = object

ReportFormat: TypeAlias = Literal["text", "json", "markdown", "md", "html", "sarif"]


def result(value: ReportValue, format_type: ReportFormat = "text") -> str:
    """Render any public workflow result in the selected format."""
    return render(value, format_type)


def render(value: ReportValue, format_type: ReportFormat = "text") -> str:
    """Render scans, verified executions, execution results, or issue collections."""
    normalized_format = _normalize_format(format_type)
    if _is_scan_result(value) or _is_scan_result_sequence(value):
        return _render_scan_result(value, normalized_format)
    if _is_verified_result(value):
        return _render_verified_result(value, normalized_format)
    if _is_issue_sequence(value):
        return issues(cast("Sequence[IssueLike]", value), normalized_format)
    return _render_execution_result(value, normalized_format)


def scan(value: ScanResult | Sequence[ScanResult], format_type: str = "text") -> str:
    """Render one scan result or a directory scan result list."""
    return _render_scan_result(value, _normalize_format(format_type))


def verification(value: VerifiedExecutionResult, format_type: str = "text") -> str:
    """Render a verified-execution result."""
    return _render_verified_result(value, _normalize_format(format_type))


def issues(values: Iterable[object], format_type: str = "text") -> str:
    """Render issue-like values in the selected output format."""
    values_list = list(values)
    normalized_format = _normalize_format(format_type)
    if normalized_format == "json":
        from pysymex._internal.api.issues import records

        return dumps(records(values_list), indent=2, default=str)
    if normalized_format == "sarif":
        return _sarif_for_issues(values_list).to_json()
    if normalized_format == "markdown":
        return _issues_to_markdown(values_list)
    if normalized_format == "html":
        return _html_document("pysymex issues", _issues_to_html(values_list))

    from pysymex._internal.api.issues import render as render_issue

    return "\n\n".join(render_issue(issue) for issue in values_list)


def text(value: ReportValue) -> str:
    """Render a public workflow result as plain text."""
    return render(value, "text")


def json(value: ReportValue) -> str:
    """Render a public workflow result as JSON text."""
    return render(value, "json")


def markdown(value: ReportValue) -> str:
    """Render a public workflow result as Markdown text."""
    return render(value, "markdown")


def sarif(value: ReportValue) -> dict[str, object]:
    """Return SARIF data for a public workflow result."""
    return _sarif_log_for_value(value).to_dict()


def save(
    value: ReportValue,
    path: str | Path,
    format_type: ReportFormat | None = None,
) -> Path:
    """Render and write a report to ``path``."""
    destination = Path(path)
    selected_format = format_type or _format_from_suffix(destination)
    rendered = render(value, selected_format)
    destination.write_text(rendered, encoding="utf-8")
    return destination


def _render_execution_result(value: object, format_type: str) -> str:
    """Render a core execution result using the existing result formatter."""
    if format_type == "sarif":
        return _sarif_log_for_value(value).to_json()
    from pysymex._internal.reporting.formatters.dispatch import format_result

    return format_result(cast("ExecutionResult", value), format_type)


def _render_verified_result(value: object, format_type: str) -> str:
    """Render a verified-execution result without forcing callers through internals."""
    if format_type == "json":
        return dumps(data(value), indent=2, default=str)
    if format_type == "sarif":
        return _sarif_log_for_value(value).to_json()
    if format_type == "markdown":
        return _verified_result_to_markdown(value)
    if format_type == "html":
        title = _verified_title(value)
        body = f"<pre>{html.escape(_verified_summary(value))}</pre>"
        return _html_document(title, body)
    return _verified_summary(value)


def _render_scan_result(value: object, format_type: str) -> str:
    """Render one scan result or a directory scan result list."""
    if format_type == "json":
        return dumps(data(value), indent=2, default=str)
    if format_type == "sarif":
        return _sarif_log_for_value(value).to_json()
    if format_type == "markdown":
        return _scan_to_markdown(value)
    if format_type == "html":
        return _html_document("pysymex scan report", _scan_to_html(value))
    return _scan_to_text(value)


def _scan_to_text(value: object) -> str:
    """Render scan output as compact plain text."""
    scan_results = _as_scan_results(value)
    lines = [
        "pysymex scan report",
        f"Files: {len(scan_results)}",
        f"Issues: {count(value)}",
        f"Clean: {'yes' if clean(value) else 'no'}",
        f"Degraded: {'yes' if degraded(value) else 'no'}",
    ]
    for item in scan_results:
        lines.extend(("", f"{item.file_path}", f"  Outcome: {item.outcome.value}"))
        if item.outcome_subreason:
            lines.append(f"  Reason: {item.outcome_subreason}")
        lines.append(f"  Issues: {len(item.issues)}")
        lines.append(f"  Paths explored: {item.paths_explored}")
        if item.error:
            lines.append(f"  Error: {item.error}")
        for issue in item.issues:
            lines.append(f"  - {_issue_one_line(issue)}")
    return "\n".join(lines)


def _scan_to_markdown(value: object) -> str:
    """Render scan output as Markdown."""
    scan_results = _as_scan_results(value)
    lines = [
        "# pysymex scan report",
        "",
        f"- Files: {len(scan_results)}",
        f"- Issues: {count(value)}",
        f"- Clean: {'yes' if clean(value) else 'no'}",
        f"- Degraded: {'yes' if degraded(value) else 'no'}",
        "",
    ]
    for item in scan_results:
        lines.extend(
            [
                f"## `{item.file_path}`",
                "",
                f"- Outcome: `{item.outcome.value}`",
                f"- Reason: `{item.outcome_subreason or 'none'}`",
                f"- Issues: {len(item.issues)}",
                f"- Paths explored: {item.paths_explored}",
                "",
            ],
        )
        if item.error:
            lines.extend((f"**Error:** {item.error}", ""))
        if item.issues:
            lines.append("### Issues")
            lines.append("")
            for issue in item.issues:
                lines.append(f"- {_issue_one_line(issue)}")
            lines.append("")
    return "\n".join(lines).rstrip()


def _scan_to_html(value: object) -> str:
    """Render scan output as simple report body HTML."""
    scan_results = _as_scan_results(value)
    parts = [
        "<section>",
        "<h1>pysymex scan report</h1>",
        "<dl>",
        f"<dt>Files</dt><dd>{len(scan_results)}</dd>",
        f"<dt>Issues</dt><dd>{count(value)}</dd>",
        f"<dt>Clean</dt><dd>{'yes' if clean(value) else 'no'}</dd>",
        f"<dt>Degraded</dt><dd>{'yes' if degraded(value) else 'no'}</dd>",
        "</dl>",
        "</section>",
    ]
    for item in scan_results:
        parts.extend(
            [
                "<section>",
                f"<h2>{html.escape(item.file_path)}</h2>",
                "<dl>",
                f"<dt>Outcome</dt><dd>{html.escape(item.outcome.value)}</dd>",
                f"<dt>Reason</dt><dd>{html.escape(item.outcome_subreason or 'none')}</dd>",
                f"<dt>Issues</dt><dd>{len(item.issues)}</dd>",
                f"<dt>Paths explored</dt><dd>{item.paths_explored}</dd>",
                "</dl>",
            ],
        )
        if item.error:
            parts.append(f"<p><strong>Error:</strong> {html.escape(item.error)}</p>")
        if item.issues:
            parts.append(_issues_to_html(item.issues))
        parts.append("</section>")
    return "\n".join(parts)


def _verified_result_to_markdown(value: object) -> str:
    """Render a verified result as Markdown."""
    result_data = data(value)
    lines = [
        "# pysymex verification report",
        "",
        f"- Function: `{result_data.get('function_name', '')}`",
        f"- Source: `{result_data.get('source_file', '')}`",
        f"- Verified: {'yes' if result_data.get('is_verified') else 'no'}",
        f"- Issues: {count(value)}",
        f"- Paths explored: {result_data.get('paths_explored', 0)}",
        "",
    ]
    all_issues = _all_issues(value)
    if all_issues:
        lines.append("## Issues")
        lines.append("")
        for issue in all_issues:
            lines.append(f"- {_issue_one_line(issue)}")
    return "\n".join(lines).rstrip()


def _issues_to_markdown(values: Sequence[object]) -> str:
    """Render issue values as Markdown."""
    lines = ["# pysymex issues", ""]
    for issue in values:
        lines.append(f"- {_issue_one_line(issue)}")
    return "\n".join(lines).rstrip()


def _issues_to_html(values: Iterable[object]) -> str:
    """Render issue values as an HTML list."""
    items = "\n".join(f"<li>{html.escape(_issue_one_line(issue))}</li>" for issue in values)
    return f"<ul>{items}</ul>"


def _issue_one_line(issue: object) -> str:
    """Render an issue as one report line."""
    from pysymex._internal.api.issues import render as render_issue

    return " ".join(render_issue(issue).split())


def _sarif_log_for_value(value: object) -> SARIFLog:
    """Build a SARIF log for scan, verify, execution, or issue-list values."""
    all_issues = _all_issues(value)
    return _sarif_for_issues(
        all_issues,
        analyzed_files=_analyzed_files(value),
        execution_successful=not all_issues and not degraded(value),
        invocation_properties=_invocation_properties(value),
    )


def _sarif_for_issues(
    values: Iterable[object],
    *,
    analyzed_files: list[str] | None = None,
    execution_successful: bool = True,
    invocation_properties: dict[str, object] | None = None,
) -> SARIFLog:
    """Build a SARIF log from issue-like values."""
    from pysymex._internal.reporting.sarif.generator import SARIFGenerator
    from pysymex._internal.api.issues import data

    issue_payloads = [_normalize_issue_dict(data(issue)) for issue in values]
    return SARIFGenerator().generate(
        issues=issue_payloads,
        analyzed_files=analyzed_files,
        execution_successful=execution_successful,
        invocation_properties=invocation_properties,
    )


def _normalize_issue_dict(data: Mapping[str, object]) -> dict[str, object]:
    """Normalize issue dictionaries into the SARIF generator input schema."""
    normalized = {str(key): value for key, value in data.items()}
    normalized.setdefault("type", normalized.get("kind", "UNKNOWN"))
    normalized.setdefault("message", "")
    if "line_number" not in normalized and "line" in normalized:
        normalized["line_number"] = normalized["line"]
    if "filename" not in normalized and "file" in normalized:
        normalized["filename"] = normalized["file"]
    return normalized


def _all_issues(value: object) -> list[object]:
    """Return all issue-like values carried by a public result shape."""
    if _is_scan_result(value):
        return list(getattr(value, "issues", []))
    if _is_scan_result_sequence(value):
        issues_list: list[object] = []
        for item in cast("Sequence[object]", value):
            issues_list.extend(getattr(item, "issues", []))
        return issues_list
    if _is_issue_sequence(value):
        return list(cast("Sequence[object]", value))
    issues_list = list(getattr(value, "issues", []) or [])
    issues_list.extend(getattr(value, "contract_issues", []) or [])
    issues_list.extend(getattr(value, "arithmetic_issues", []) or [])
    return issues_list


def _analyzed_files(value: object) -> list[str] | None:
    """Return analyzed file paths when the result shape carries them."""
    if _is_scan_result(value):
        return [str(getattr(value, "file_path", ""))]
    if _is_scan_result_sequence(value):
        return [str(getattr(item, "file_path", "")) for item in cast("Sequence[object]", value)]
    source_file = getattr(value, "source_file", "")
    if source_file:
        return [str(source_file)]
    return None


def _invocation_properties(value: object) -> dict[str, object] | None:
    """Return common SARIF invocation properties for a public result shape."""
    if _is_scan_result_sequence(value):
        return cast("dict[str, object]", data(value).get("summary"))
    properties: dict[str, object] = {}
    for name in (
        "paths_explored",
        "paths_completed",
        "paths_pruned",
        "elapsed_time",
        "total_time_seconds",
        "code_objects",
    ):
        attr = getattr(value, name, None)
        if attr is not None:
            properties[name] = attr
    degraded_passes = getattr(value, "degraded_passes", None)
    if degraded_passes:
        properties["degraded_passes"] = list(degraded_passes)
    return properties or None


def _verified_summary(value: object) -> str:
    """Return the verified result's own summary when available."""
    summary_method = getattr(value, "format_summary", None)
    if callable(summary_method):
        return str(summary_method())
    return dumps(data(value), indent=2, default=str)


def _verified_title(value: object) -> str:
    """Return an HTML title for a verified result."""
    function_name = getattr(value, "function_name", "")
    return f"pysymex verification: {function_name}" if function_name else "pysymex verification"


def _as_scan_results(value: object) -> list[ScanResult]:
    """Return a list of scan results from one scan result or a sequence."""
    if _is_scan_result(value):
        return [cast("ScanResult", value)]
    return list(cast("Sequence[ScanResult]", value))


def _is_scan_result(value: object) -> bool:
    """Return whether *value* is a scan result."""
    from pysymex._internal.scanner.types import ScanResult

    return isinstance(value, ScanResult)


def _is_scan_result_sequence(value: object) -> bool:
    """Return whether *value* is a non-string sequence of scan results."""
    if isinstance(value, (str, bytes, bytearray)):
        return False
    if not isinstance(value, Sequence):
        return False
    return all(_is_scan_result(item) for item in cast("Sequence[object]", value))


def _is_verified_result(value: object) -> bool:
    """Return whether *value* is a verified-execution result."""
    from pysymex._internal.execution.executors.verified.types import VerifiedExecutionResult

    return isinstance(value, VerifiedExecutionResult)


def _is_issue_sequence(value: object) -> bool:
    """Return whether *value* appears to be a sequence of issue-like values."""
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        return False
    if not isinstance(value, Sequence):
        return False
    sequence = cast("Sequence[object]", value)
    return bool(sequence) and all(_is_issue_like(item) for item in sequence)


def _is_issue_like(value: object) -> bool:
    """Return whether *value* looks like a public issue record."""
    if isinstance(value, Mapping):
        return "message" in value or "kind" in value or "type" in value
    return hasattr(value, "message") or hasattr(value, "format")


def _normalize_format(format_type: str) -> str:
    """Normalize report format aliases."""
    normalized = format_type.lower()
    return "markdown" if normalized == "md" else normalized


def _format_from_suffix(path: Path) -> ReportFormat:
    """Infer report format from an output path suffix."""
    suffix = path.suffix.lower().lstrip(".")
    if suffix == "md":
        return "markdown"
    if suffix in {"json", "html", "sarif", "markdown", "text"}:
        return cast("ReportFormat", suffix)
    return "text"


def _html_document(title: str, body: str) -> str:
    """Wrap an HTML body in a small standalone document."""
    escaped_title = html.escape(title)
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            f"<title>{escaped_title}</title>",
            "<style>",
            "body{font-family:system-ui,sans-serif;line-height:1.45;margin:2rem;max-width:72rem}",
            "section{border-top:1px solid #ddd;padding:1rem 0}",
            "dt{font-weight:700;float:left;clear:left;margin-right:.5rem}",
            "dd{margin:0 0 .25rem 9rem}",
            "pre{background:#f6f8fa;padding:1rem;overflow:auto}",
            "</style>",
            "</head>",
            "<body>",
            body,
            "</body>",
            "</html>",
        ],
    )


__all__ = [
    "issues",
    "json",
    "markdown",
    "render",
    "result",
    "sarif",
    "save",
    "scan",
    "text",
    "verification",
]
