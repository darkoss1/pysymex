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

"""Contract-verification text formatter implementation."""

from __future__ import annotations

from typing import Any, Sequence, cast

from pysymex.cli.formatters.base import (
    format_verify_issue,
    verify_issue_count,
    verify_result_to_dict,
)
from pysymex.config import VERSION


class VerifyTextMixin:
    """Formats contract verification results for the human-readable text formatter."""

    def _format_verify_ascii(self, results: Sequence[Any], total: int, duration: float) -> str:
        """Format formal verification results as plain ASCII text.

        Args:
            results (Sequence[Any]): Sequence of verification results.
            total (int): Total number of verification issues found.
            duration (float): Verification execution duration in seconds.

        Returns:
            str: Plain ASCII text formatted report.
        """
        degraded_count = sum(1 for result in results if getattr(result, "degraded_passes", []))
        lines = [
            "",
            "+" + "-" * 58 + "+",
            "|" + "  [*] pysymex contract verification".center(58) + "|",
            "+" + "-" * 58 + "+",
            "",
        ]

        if not results:
            lines.append("  [WARN] No contracted functions were verified.")
        elif total == 0 and degraded_count == 0:
            lines.append("  [OK] All selected contracts verified.")
        elif total == 0:
            lines.append("  [!] No findings reported; verification was degraded.")
        else:
            lines.append(f"  [!] Findings: {total}")
        lines.append("")

        for result in results:
            data = verify_result_to_dict(result)
            status = (
                "[OK]" if data["total_issues"] == 0 and not data["analysis_degraded"] else "[!]"
            )
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
            contract_evidence = data["contract_evidence"]
            if isinstance(contract_evidence, list) and contract_evidence:
                lines.append("      Contract evidence:")
                for evidence in cast("list[dict[str, object]]", contract_evidence):
                    lines.append(f"        - {_format_contract_evidence_row(evidence)}")
            termination = data["termination"]
            if isinstance(termination, dict):
                lines.append(
                    f"      Termination: {termination['status']} - {termination['message']}"
                )
            degraded_passes = data["degraded_passes"]
            if isinstance(degraded_passes, list) and degraded_passes:
                lines.append(
                    f"      Analysis degraded: {', '.join(cast('list[str]', degraded_passes))}"
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
        lines.append(f"  Degraded analyses:  {degraded_count}")
        lines.append(f"  Execution time:     {duration:.2f}s")
        lines.append("")
        lines.append("---" * 60)
        return "\n".join(lines)

    def _format_verify_rich(self, results: Sequence[Any], total: int, duration: float) -> str:
        """Format formal verification results using rich terminal components.

        Args:
            results (Sequence[Any]): Sequence of verification results.
            total (int): Total number of verification issues found.
            duration (float): Verification execution duration in seconds.

        Returns:
            str: Rich text formatted report with panels, tables, and colors.
        """
        from io import StringIO

        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console(file=StringIO(), force_terminal=True, width=100)
        console.print(Panel("pysymex contract verification", border_style="cyan", box=box.ROUNDED))
        console.print()

        degraded_results = [result for result in results if getattr(result, "degraded_passes", [])]
        if not results:
            console.print("[yellow]No contracted functions were verified.[/yellow]")
            console.print()
        elif total == 0 and not degraded_results:
            console.print("[green]All selected contracts verified.[/green]")
            console.print()
        elif total == 0:
            console.print(
                "[bold yellow]No findings reported; verification was degraded.[/bold yellow]"
            )
            for result in degraded_results:
                console.print(
                    f"{getattr(result, 'function_name', 'unknown')}: "
                    f"{', '.join(getattr(result, 'degraded_passes'))}"
                )
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
        if degraded_results:
            summary.add_row(
                "Degraded analyses:", f"[bold yellow]{len(degraded_results)}[/bold yellow]"
            )
        summary.add_row("Execution time:", f"{duration:.2f}s")
        for result in results:
            summary.add_row(
                f"{getattr(result, 'function_name', 'unknown')} paths:",
                f"{getattr(result, 'paths_explored', 0)} explored, "
                f"{getattr(result, 'paths_completed', 0)} completed",
            )
        console.print(summary)
        evidence_rows = _contract_evidence_rows(results)
        if evidence_rows:
            evidence_table = Table(title="Contract evidence", box=box.ROUNDED)
            evidence_table.add_column("Function", style="bold")
            evidence_table.add_column("Status")
            evidence_table.add_column("Kind")
            evidence_table.add_column("Query")
            evidence_table.add_column("Frontend")
            evidence_table.add_column("Condition")
            for row in evidence_rows:
                evidence_table.add_row(*row)
            console.print()
            console.print(evidence_table)
        console.print()
        console.print(f"pysymex v{VERSION} | https://github.com/darkoss1/pysymex")
        return console.file.getvalue()


def _contract_evidence_rows(results: Sequence[Any]) -> list[tuple[str, str, str, str, str, str]]:
    """Return compact contract evidence rows grouped by verified result."""
    rows: list[tuple[str, str, str, str, str, str]] = []
    for result in results:
        data = verify_result_to_dict(result)
        function_name = str(data["function_name"])
        contract_evidence = data["contract_evidence"]
        if not isinstance(contract_evidence, list):
            continue
        for evidence in cast("list[dict[str, object]]", contract_evidence):
            rows.append(
                (
                    function_name,
                    str(evidence["status"]),
                    str(evidence["kind"]),
                    str(evidence["query_kind"]),
                    str(evidence["frontend"]),
                    str(evidence["condition"]),
                )
            )
    return rows


def _format_contract_evidence_row(evidence: dict[str, object]) -> str:
    """Format one compact ASCII contract evidence row."""
    return (
        f"[{evidence['status']}] {evidence['kind']} "
        f"{evidence['hook']}/{evidence['query_kind']} "
        f"({evidence['frontend']}): {evidence['condition']}"
    )
