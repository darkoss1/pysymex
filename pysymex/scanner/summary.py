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

"""Scanner progress and summary formatting.

Part of the console output and reporting layer. Formats and outputs real-time progress indicators
and final summaries of issues, execution errors, and coverage breakdowns to stdout.
"""

from __future__ import annotations

from pathlib import Path

from pysymex.analysis.detectors.protocols import ScanReporter
from pysymex.logger import get_logger
from pysymex.scanner.session import session_var
from pysymex.scanner.types import ScanResult

logger = get_logger(__name__)


def descending_issue_count(item: tuple[str, int]) -> int:
    """Helper key function to sort issue records by count in descending order.

    Args:
        item (tuple[str, int]): A tuple consisting of the issue type and its count.

    Returns:
        int: The negative value of the count, used to achieve descending order.
    """
    return -item[1]


def print_parallel_progress(
    completed: int,
    total: int,
    file_path: Path,
    result: ScanResult | None,
) -> None:
    """Print a single progress line for parallel scanning.

    Args:
        completed: The number of files completed so far.
        total: The total number of files to scan.
        file_path: The file path of the completed file.
        result: The scan result of the file, or ``None`` if it failed or crashed.

    Side Effects:
        Writes a status line directly to stdout.
    """
    pct = completed * 100 // total if total > 0 else 0
    status = "[OK]"
    if result is None or result.error:
        status = "[X]"
    elif result.degraded_passes:
        status = "[!]"
    elif result.issues:
        status = f"[!] {len(result.issues)}"
    print(f"[{completed}/{total}] ({pct}%) {file_path.name} {status}")


def print_scan_summary(results: list[ScanResult], total_files: int) -> None:
    """Print end-of-scan summary.

    Args:
        results: List of completed scan results.
        total_files: The total number of files in the scan scope.

    Side Effects:
        Writes summary details directly to stdout and logs via ``logger``.
    """
    total_issues = sum(len(r.issues) for r in results)
    files_with_issues = sum(1 for r in results if r.issues)
    errors = sum(1 for r in results if r.error)
    degraded = sum(1 for r in results if r.degraded_passes)
    logger.verbose(
        "Scan summary results=%d total_files=%d issues=%d files_with_issues=%d errors=%d degraded=%d",
        len(results),
        total_files,
        total_issues,
        files_with_issues,
        errors,
        degraded,
    )
    print(f"\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files", end="")
    if errors:
        print(f" ({errors} errors, {degraded} degraded)")
    elif degraded:
        print(f" ({degraded} degraded)")
    else:
        print()
    if len(results) < total_files:
        print(f"  [!] {total_files - len(results)} file(s) could not be scanned")


def print_final_summary(reporter: ScanReporter | None = None) -> None:
    """Print a formatted session summary to stdout.

    Reads the current :class:`~pysymex.scanner.types.ScanSession` from :data:`~pysymex.scanner.session.session_var` and
    displays file counts, issue breakdown, and the log-file path.
    Does nothing if no session is active.

    Args:
        reporter: Optional reporter to notify with session summaries.

    Side Effects:
        Writes session metrics, error summaries, and histograms directly to stdout.
    """
    session = session_var.get()
    if not session:
        logger.verbose("Final scan summary skipped; no active session")
        return
    if reporter:
        on_session_summary = getattr(reporter, "on_session_summary", None)
        if callable(on_session_summary):
            on_session_summary(session)
            return
    summary = session.get_summary()
    logger.verbose(
        "Final scan session summary files=%s issues=%s errors=%s",
        summary["files_scanned"],
        summary["total_issues"],
        summary["files_error"],
    )
    print(f"\n\n{'=' * 70}")
    print("\U0001f4cb SESSION SUMMARY")
    print("=" * 70)
    print(f"   Files scanned:     {summary['files_scanned']}")
    print(f"   Files with issues: {summary['files_with_issues']}")
    print(f"   Files clean:       {summary['files_clean']}")
    print(f"   Files with errors: {summary['files_error']}")
    print(f"   Files degraded:    {summary['files_degraded']}")
    print(f"   Total issues:      {summary['total_issues']}")
    print()
    issue_breakdown = summary["issue_breakdown"]
    if issue_breakdown:
        print("   Issue breakdown:")
        for kind, count in sorted(issue_breakdown.items(), key=descending_issue_count):
            bar = "\u2588" * min(count, 30)
            print(f"      {kind:<25} {count:>4} {bar}")
    if session.log_write_error is not None:
        print(f"\n   [X] Log not saved to {session.log_file}: {session.log_write_error}")
    else:
        print(f"\n   \U0001f4c1 Log saved to: {session.log_file}")
    print("=" * 70)
