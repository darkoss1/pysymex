# pysymex: Python Symbolic Execution & Formal Verification
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

"""Human-readable text/Rich formatters for scan results."""

from __future__ import annotations

import importlib.util
from collections import defaultdict
from typing import Any, Mapping, Sequence, cast

from pysymex.config import VERSION
from pysymex.cli.formatters.base import (
    Formatter,
    format_verify_issue,
    verify_issue_count,
    verify_result_to_dict,
)


def _issue_line_for_sort(issue: object) -> int:
    line_val = getattr(issue, "line", 0)
    return line_val if isinstance(line_val, int) else 0


class TextFormatter(Formatter):
    """Outputs human-readable CLI reports, using Rich if available."""

    def __init__(self, use_rich: bool = True):
        self.use_rich = use_rich
        if self.use_rich:
            self.has_rich = importlib.util.find_spec("rich") is not None
        else:
            self.has_rich = False

    def format_static(
        self,
        issues: Sequence[Any],
        total: int,
        suppressed: int,
        duration: float,
    ) -> str:
        if self.has_rich:
            return self._format_static_rich(issues, total, suppressed)
        return self._format_static_ascii(issues, total, suppressed)

    def format_pipeline(
        self,
        results: Mapping[str, Any],
        all_issues: list[tuple[str, Any]],
        total: int,
        duration: float,
    ) -> str:
        if self.has_rich:
            return self._format_pipeline_rich(results, all_issues, total)
        return self._format_pipeline_ascii(results, all_issues, total)

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        if self.has_rich:
            return self._format_symbolic_rich(results, total, reproduce, duration)
        return self._format_symbolic_ascii(results, total, reproduce, duration)

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        if self.has_rich:
            return self._format_verify_rich(results, total, duration)
        return self._format_verify_ascii(results, total, duration)

    # --- Static Implementations ---

    def _format_static_ascii(self, issues: Sequence[Any], total: int, suppressed: int) -> str:
        lines = [
            "",
            "+" + "-" * 58 + "+",
            "|" + "  [*] pysymex static scan".center(58) + "|",
            "+" + "-" * 58 + "+",
            "",
        ]
        lines.append(f"  [BUGS] Issues:  {total}")
        if suppressed > 0:
            lines.append(f"  [SUPPRESSED] Suppressed:  {suppressed} (likely false positives)")
        lines.append("")

        if total == 0:
            lines.append("  [OK] No issues found!")
        else:
            by_file: defaultdict[str, list[object]] = defaultdict(list)
            for issue in issues:
                by_file[str(getattr(issue, "file", "unknown"))].append(issue)

            for fpath, file_issues in by_file.items():
                lines.append(f"  --------- {fpath} ---------")
                for issue in sorted(file_issues, key=_issue_line_for_sort):
                    icon = {"error": "[!]", "warning": "[!]"}.get(
                        str(getattr(issue, "severity", "warning")), "[INFO]"
                    )
                    kind = getattr(issue, "kind", "UNKNOWN")
                    line = getattr(issue, "line", "?")
                    message = getattr(issue, "message", "")
                    lines.append(f"    {icon} [{kind}] Line {line}: {message}")
                    suggestion = getattr(issue, "suggestion", None)
                    if isinstance(suggestion, str) and suggestion:
                        lines.append(f"       [SUGGESTION] {suggestion}")
        lines.extend(["", "---" * 60])
        return "\n".join(lines)

    def _format_static_rich(self, issues: Sequence[Any], total: int, suppressed: int) -> str:
        from io import StringIO
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console(file=StringIO(), force_terminal=True, width=100)
        console.print(Panel("pysymex static scan", border_style="cyan", box=box.ROUNDED))
        console.print()

        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold")
        summary.add_column()
        summary.add_row(
            "Issues", f"[bold red]{total}[/bold red]" if total > 0 else "[green]0[/green]"
        )
        if suppressed > 0:
            summary.add_row("Suppressed", str(suppressed))
        console.print(summary)
        console.print()

        if total == 0:
            console.print("[green]No issues found![/green]")
            return str(cast(Any, console.file).getvalue())

        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("Line", justify="right")
        table.add_column("Kind", style="yellow")
        table.add_column("Severity")
        table.add_column("Message")
        for issue_obj in sorted(
            issues,
            key=lambda i: (str(getattr(i, "file", "unknown")), _issue_line_for_sort(i)),
        ):
            sev = str(getattr(issue_obj, "severity", "warning"))
            sev_style = "red" if sev == "error" else "yellow"
            table.add_row(
                str(getattr(issue_obj, "file", "unknown")),
                str(getattr(issue_obj, "line", "?")),
                str(getattr(issue_obj, "kind", "UNKNOWN")),
                f"[{sev_style}]{sev}[/{sev_style}]",
                str(getattr(issue_obj, "message", "")),
            )
        console.print(table)
        return str(cast(Any, console.file).getvalue())

    # --- Pipeline Implementations ---

    def _format_pipeline_ascii(
        self, results: Mapping[str, Any], all_issues: list[tuple[str, Any]], total: int
    ) -> str:
        lines = [
            "",
            "+" + "=" * 58 + "+",
            "|" + "  pysymex pipeline scan".center(58) + "|",
            "+" + "=" * 58 + "+",
            "",
            f"  Files: {len(results)}",
            f"  Issues: {total}",
            "",
        ]
        if total == 0:
            lines.append("  No issues found!")
        else:
            for file_path, issue in all_issues:
                sev = getattr(issue, "severity", None)
                sev_name = sev.name if sev is not None and hasattr(sev, "name") else str(sev)
                lines.append(
                    f"  [{sev_name}] {file_path}:{getattr(issue, 'line', '?')} "
                    f"- {getattr(issue, 'message', '')}"
                )
        lines.extend(["", "-" * 60])
        return "\n".join(lines)

    def _format_pipeline_rich(
        self, results: Mapping[str, Any], all_issues: list[tuple[str, Any]], total_issues: int
    ) -> str:
        from io import StringIO
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console(file=StringIO(), force_terminal=True, width=100)
        console.print(Panel("pysymex pipeline scan", border_style="cyan", box=box.ROUNDED))
        console.print()

        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold")
        summary.add_column()
        summary.add_row("Files", str(len(results)))
        summary.add_row(
            "Issues",
            f"[bold red]{total_issues}[/bold red]" if total_issues > 0 else "[green]0[/green]",
        )
        console.print(summary)
        console.print()

        if total_issues == 0:
            console.print("[green]No issues found![/green]")
            return str(cast(Any, console.file).getvalue())

        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("Line", justify="right")
        table.add_column("Severity")
        table.add_column("Message")
        for file_path, issue in all_issues:
            sev = getattr(issue, "severity", None)
            sev_name = sev.name if sev is not None and hasattr(sev, "name") else str(sev)
            sev_l = sev_name.lower()
            sev_style = "red" if sev_l in {"error", "high"} else "yellow"
            table.add_row(
                str(file_path),
                str(getattr(issue, "line", "?")),
                f"[{sev_style}]{sev_name}[/{sev_style}]",
                str(getattr(issue, "message", "")),
            )
        console.print(table)
        return str(cast(Any, console.file).getvalue())

    # --- Symbolic Implementations ---

    def _format_symbolic_ascii(
        self, results: Sequence[Any], total: int, reproduce: bool, duration: float
    ) -> str:
        lines = [
            "",
            "+" + "-" * 58 + "+",
            "|" + "  [*] pysymex - formal verification report".center(58) + "|",
            "+" + "-" * 58 + "+",
            "",
        ]

        valid_results = [r for r in results if hasattr(r, "elapsed_time")]

        if total == 0:
            lines.append("  [OK] No issues found!")
        else:
            for scan_result in valid_results:
                issues = getattr(scan_result, "issues", [])
                if not issues:
                    continue
                file_path = getattr(scan_result, "file_path", "unknown")
                lines.append(f"  --------- {file_path} ---------")
                for issue in issues:
                    if not isinstance(issue, dict):
                        continue
                    issue_dict = cast("dict[str, Any]", issue)
                    kind = issue_dict.get("kind", "UNKNOWN")
                    icon = (
                        "[!"
                        if kind
                        in ("DIVISION_BY_ZERO", "ASSERTION_ERROR", "INDEX_ERROR", "KEY_ERROR")
                        else "[INFO]"
                    )
                    lines.append(
                        f"    {icon} [{kind}] Line {issue_dict.get('line', '?')}: {issue_dict.get('message', '')}"
                    )
                    ce = issue_dict.get("counterexample")
                    if isinstance(ce, dict):
                        lines.append(f"       -> Trigger: {ce}")

                if reproduce:
                    from pysymex.analysis.detectors import Issue, IssueKind
                    from pysymex.reporting.reproduction import ReproductionGenerator

                    gen = ReproductionGenerator()
                    lines.extend(["", "    [!] Reproduction Scripts:"])
                    for issue in issues:
                        if not isinstance(issue, dict):
                            continue
                        issue_dict = cast("dict[str, Any]", issue)
                        ce = issue_dict.get("counterexample")
                        if isinstance(ce, dict):
                            issue_kind = IssueKind.__members__.get(
                                str(issue_dict.get("kind", IssueKind.UNKNOWN)), IssueKind.UNKNOWN
                            )
                            issue_obj = Issue(
                                kind=issue_kind,
                                message=str(issue_dict.get("message", "")),
                                function_name=str(issue_dict.get("function_name", "unknown")),
                                class_name=issue_dict.get("class_name")
                                if isinstance(issue_dict.get("class_name", ""), str)
                                else None,
                                counterexample=cast("dict[str, object]", ce),
                                filename=str(file_path),
                            )
                            script = gen.generate_script(issue_obj)
                            if script:
                                lines.append(f"       + {script}")

        lines.append("")
        lines.append("  [SUMMARY]")
        lines.append("  " + "-" * 58)
        lines.append(f"  Files scanned:    {len(results)}")
        lines.append(f"  Issues found:     {total}")
        if valid_results:
            mems = [r.avg_memory_mb for r in valid_results if getattr(r, "avg_memory_mb", 0) > 0]
            avg_mem = sum(mems) / len(mems) if mems else 0.0
            lines.append(f"  Execution time:   {duration:.2f}s")
            lines.append(f"  Memory (avg):     {avg_mem:.2f} MB")
        lines.append("")
        lines.append("---" * 60)
        return "\n".join(lines)

    def _format_symbolic_rich(
        self, results: Sequence[Any], total: int, reproduce: bool, duration: float
    ) -> str:
        from io import StringIO
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console(file=StringIO(), force_terminal=True, width=80)

        header = Panel("pysymex - formal verification report", border_style="cyan", box=box.ROUNDED)
        console.print(header)
        console.print()

        valid_results = [r for r in results if hasattr(r, "elapsed_time")]
        error_results = [r for r in results if getattr(r, "error", None)]
        console.print()

        if error_results:
            console.print("[bold red]SCAN ERRORS[/bold red]")
            console.print("[dim]" + "─" * 60 + "[/dim]")
            for r in error_results:
                console.print(f"[bold red]File:[/bold red] {r.file_path}")
                console.print(f"[red]Error:[/red] {r.error}")
                console.print()
            console.print()

        if total > 0:
            console.print(f"[bold red]ISSUES FOUND ({total})[/bold red]")
            console.print("[dim]" + "─" * 60 + "[/dim]")

            for scan_result in valid_results:
                issues = getattr(scan_result, "issues", [])
                if not issues:
                    continue

                file_path = getattr(scan_result, "file_path", "unknown")
                console.print(f"[bold cyan]{file_path}[/bold cyan]")

                for issue in issues:
                    if not isinstance(issue, dict):
                        continue
                    issue_dict = cast("dict[str, Any]", issue)
                    kind = issue_dict.get("kind", "UNKNOWN")
                    line = issue_dict.get("line", "?")
                    message = issue_dict.get("message", "")

                    issue_details = (
                        f"[bold red]Location:[/bold red] {file_path}:{line}\n"
                        f"[bold red]Type:[/bold red]    {kind}\n"
                        f"[bold red]Error:[/bold red]    {message}"
                    )

                    ce = issue_dict.get("counterexample")
                    if isinstance(ce, dict):
                        issue_details += "\n[bold red]Trigger:[/bold red]  [bold yellow]"
                        for name, value in sorted(cast("dict[Any, Any]", ce).items()):
                            issue_details += f"{name} = {value}, "
                        issue_details = issue_details.rstrip(", ")
                        issue_details += "[/bold yellow]"

                    issue_panel = Panel(
                        issue_details,
                        title=f"[bold red][ {kind} ][/bold red]",
                        title_align="left",
                        border_style="red",
                        box=box.ROUNDED,
                        padding=(0, 2),
                    )
                    console.print(issue_panel)
                console.print()

            if reproduce:
                from pysymex.analysis.detectors import Issue, IssueKind
                from pysymex.reporting.reproduction import ReproductionGenerator

                console.print("[bold yellow]Reproduction Scripts:[/bold yellow]")

                for scan_result in valid_results:
                    issues = getattr(scan_result, "issues", [])
                    file_path = getattr(scan_result, "file_path", "unknown")
                    for issue in issues:
                        if not isinstance(issue, dict):
                            continue
                        issue_dict = cast("dict[str, Any]", issue)
                        ce = issue_dict.get("counterexample")
                        if isinstance(ce, dict):
                            issue_kind = IssueKind.__members__.get(
                                str(issue_dict.get("kind", IssueKind.UNKNOWN)), IssueKind.UNKNOWN
                            )
                            issue_obj = Issue(
                                kind=issue_kind,
                                message=str(issue_dict.get("message", "")),
                                function_name=str(issue_dict.get("function_name", "unknown")),
                                class_name=issue_dict.get("class_name")
                                if isinstance(issue_dict.get("class_name", ""), str)
                                else None,
                                counterexample=cast("dict[str, object]", ce),
                                filename=str(file_path),
                                line_number=int(issue_dict.get("line", 0)),
                                pc=0,
                                constraints=[],
                            )
                            gen = ReproductionGenerator()
                            script_path = gen.generate_script(issue_obj)
                            console.print(f"  • {script_path}")
        elif not results:
            console.print("[yellow]No files were scanned.[/yellow]")
            console.print()
        elif not error_results:
            console.print("[green]No issues found![/green]")
            console.print()

        console.print("[dim]" + "─" * 80 + "[/dim]")
        console.print("[bold blue]SUMMARY[/bold blue]")
        console.print("[dim]" + "─" * 60 + "[/dim]")

        summary_grid = Table.grid(padding=(0, 3))
        summary_grid.add_column(style="bold white", justify="left")
        summary_grid.add_column(style="cyan", justify="right")

        summary_grid.add_row("Files scanned:", str(len(results)))
        summary_grid.add_row(
            "Issues found:", f"[bold red]{total}[/bold red]" if total > 0 else "[green]0[/green]"
        )

        if error_results:
            summary_grid.add_row("Scan errors:", f"[bold red]{len(error_results)}[/bold red]")

        if valid_results:
            mems = [r.avg_memory_mb for r in valid_results if getattr(r, "avg_memory_mb", 0) > 0]
            avg_mem = sum(mems) / len(mems) if mems else 0.0
            summary_grid.add_row("Execution time:", f"{duration:.2f}s")
            summary_grid.add_row("Memory (avg):", f"{avg_mem:.2f} MB")

        console.print(summary_grid)
        console.print()
        console.print(f"pysymex v{VERSION} | https://github.com/darkoss1/pysymex")
        return str(cast(Any, console.file).getvalue())

    # --- Verify Implementations ---

    def _format_verify_ascii(self, results: Sequence[Any], total: int, duration: float) -> str:
        lines = [
            "",
            "+" + "-" * 58 + "+",
            "|" + "  [*] pysymex contract verification".center(58) + "|",
            "+" + "-" * 58 + "+",
            "",
        ]

        if not results:
            lines.append("  [WARN] No contracted functions were verified.")
        elif total == 0:
            lines.append("  [OK] All selected contracts verified.")
        else:
            lines.append(f"  [!] Findings: {total}")
        lines.append("")

        for result in results:
            data = verify_result_to_dict(result)
            status = "[OK]" if data["total_issues"] == 0 else "[!]"
            lines.append(f"  {status} {data['function_name']}")
            source_file = data["source_file"]
            if source_file:
                lines.append(f"      File: {source_file}")
            lines.append(
                "      Paths: "
                f"{data['paths_explored']} explored, {data['paths_completed']} completed"
            )
            lines.append(
                "      Contracts: "
                f"{data['contracts_verified']}/{data['contracts_checked']} verified"
            )
            termination = data["termination"]
            if isinstance(termination, dict):
                lines.append(
                    f"      Termination: {termination['status']} - {termination['message']}"
                )

            for section, heading in (
                ("runtime_issues", "Runtime issues"),
                ("contract_issues", "Contract issues"),
                ("arithmetic_issues", "Arithmetic issues"),
            ):
                issues = data[section]
                if isinstance(issues, list) and issues:
                    lines.append(f"      {heading}:")
                    lines.extend(f"        - {issue}" for issue in cast("list[object]", issues))
            lines.append("")

        lines.append("  [SUMMARY]")
        lines.append("  " + "-" * 58)
        lines.append(f"  Functions verified: {len(results)}")
        lines.append(f"  Findings:           {total}")
        lines.append(f"  Execution time:     {duration:.2f}s")
        lines.append("")
        lines.append("---" * 60)
        return "\n".join(lines)

    def _format_verify_rich(self, results: Sequence[Any], total: int, duration: float) -> str:
        from io import StringIO
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console(file=StringIO(), force_terminal=True, width=100)
        console.print(Panel("pysymex contract verification", border_style="cyan", box=box.ROUNDED))
        console.print()

        if not results:
            console.print("[yellow]No contracted functions were verified.[/yellow]")
            console.print()
        elif total == 0:
            console.print("[green]All selected contracts verified.[/green]")
            console.print()
        else:
            console.print(f"[bold red]FINDINGS ({total})[/bold red]")
            console.print("[dim]" + "─" * 60 + "[/dim]")
            for result in results:
                if verify_issue_count(result) == 0:
                    continue
                details: list[str] = []
                for section_name, issues in (
                    ("Runtime", getattr(result, "issues", [])),
                    ("Contract", getattr(result, "contract_issues", [])),
                    ("Arithmetic", getattr(result, "arithmetic_issues", [])),
                ):
                    for issue in issues:
                        details.append(f"[bold]{section_name}:[/bold] {format_verify_issue(issue)}")
                console.print(
                    Panel(
                        "\n".join(details),
                        title=f"[bold red]{getattr(result, 'function_name', 'unknown')}[/bold red]",
                        border_style="red",
                        box=box.ROUNDED,
                    )
                )
            console.print()

        summary = Table.grid(padding=(0, 3))
        summary.add_column(style="bold white")
        summary.add_column(style="cyan", justify="right")
        summary.add_row("Functions verified:", str(len(results)))
        summary.add_row(
            "Findings:", f"[bold red]{total}[/bold red]" if total > 0 else "[green]0[/green]"
        )
        summary.add_row("Execution time:", f"{duration:.2f}s")
        for result in results:
            summary.add_row(
                f"{getattr(result, 'function_name', 'unknown')} paths:",
                f"{getattr(result, 'paths_explored', 0)} explored, "
                f"{getattr(result, 'paths_completed', 0)} completed",
            )
        console.print(summary)
        console.print()
        console.print(f"pysymex v{VERSION} | https://github.com/darkoss1/pysymex")
        return str(cast(Any, console.file).getvalue())
