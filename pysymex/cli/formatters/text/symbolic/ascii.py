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

"""ASCII symbolic scan text formatting."""

from __future__ import annotations

from typing import Any, Sequence, cast

from pysymex.analysis.scan.records import normalize_trigger_input


class SymbolicAsciiMixin:
    """ASCII renderer for symbolic scan results."""

    def _format_symbolic_ascii(
        self, results: Sequence[Any], total: int, reproduce: bool, duration: float
    ) -> str:
        """Format symbolic execution scan results as plain ASCII text.

        Args:
            results (Sequence[Any]): Sequence of symbolic execution results.
            total (int): Total number of issues found.
            reproduce (bool): True if reproduction test cases are requested, False otherwise.
            duration (float): Execution duration in seconds.

        Returns:
            str: Plain ASCII text formatted report.
        """
        lines = [
            "",
            "+" + "-" * 58 + "+",
            "|" + "  [*] pysymex - formal verification report".center(58) + "|",
            "+" + "-" * 58 + "+",
            "",
        ]

        valid_results = [r for r in results if hasattr(r, "elapsed_time")]
        error_results = [r for r in results if getattr(r, "error", None)]
        degraded_results = [r for r in results if getattr(r, "degraded_passes", [])]

        if error_results:
            lines.append("  [X] Scan errors:")
            for result in error_results:
                lines.append(f"      {result.file_path}: {result.error}")
            lines.append("")

        if degraded_results:
            lines.append("  [!] Degraded analyses:")
            for result in degraded_results:
                lines.append(f"      {result.file_path}: {', '.join(result.degraded_passes)}")
            lines.append("")

        if total == 0 and not error_results and not degraded_results:
            lines.append("  [OK] No issues found!")
        elif total > 0:
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
                        f"    {icon} [{kind}] Line {issue_dict.get('line', '?')}: "
                        f"{issue_dict.get('message', '')}"
                    )
                    ce = normalize_trigger_input(issue_dict.get("counterexample"))
                    if ce is not None:
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
                        ce = normalize_trigger_input(issue_dict.get("counterexample"))
                        if ce is not None:
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
                                counterexample=ce,
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
        if error_results:
            lines.append(f"  Scan errors:      {len(error_results)}")
        if degraded_results:
            lines.append(f"  Degraded scans:   {len(degraded_results)}")
        if valid_results:
            mems = [r.avg_memory_mb for r in valid_results if getattr(r, "avg_memory_mb", 0) > 0]
            avg_mem = sum(mems) / len(mems) if mems else 0.0
            lines.append(f"  Execution time:   {duration:.2f}s")
            lines.append(f"  Memory (avg):     {avg_mem:.2f} MB")
        lines.append("")
        lines.append("---" * 60)
        return "\n".join(lines)


__all__ = ["SymbolicAsciiMixin"]
