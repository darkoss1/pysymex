"""Console-based scan reporter for CLI output.

Implements the :class:`~pysymex.analysis.detectors.protocols.ScanReporter`
protocol — all emoji / colour / progress-bar logic lives here, keeping
``scanner.core`` free of presentation concerns.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path


class ConsoleScanReporter:
    """Pretty-prints scan progress and results to stdout.

    This is the default reporter wired in by CLI entry-points.  Library
    users can pass ``reporter=None`` to ``scan_directory`` for silent
    operation, or supply their own ``ScanReporter``-compatible object.
    """

    def on_file_start(self, file_path: object) -> None:
        print(f"\n{'=' * 70}")
        print(f"\U0001f50d Scanning: {file_path}")
        print("=" * 70)

    def on_file_done(self, _file_path: object, result: object) -> None:
        if result.issues:
            print(f"\n\u26a0\ufe0f  Found {len(result.issues)} potential issues:\n")
            for issue in result.issues:
                print(f"   \u2022 [{issue['kind']}] {issue['message']} (Line {issue['line']})")
                if issue.get("counterexample"):
                    for var, val in issue["counterexample"].items():
                        print(f"       \u2514\u2500 {var} = {val}")
        elif result.error:
            print(f"\n\u274c {result.error}")
        else:
            print("\n\u2705 No issues found!")
        print(
            f"\n   \U0001f4ca Stats: {result.code_objects} code objects"
            f" | {result.paths_explored} paths explored"
        )

    def on_issue(self, issue: dict[str, object]) -> None:
        print(f"   \u2022 [{issue['kind']}] {issue['message']} (Line {issue['line']})")

    def on_error(self, _file_path: object, error: str) -> None:
        print(f"\n\u274c {error}")

    def on_progress(
        self,
        completed: int,
        total: int,
        file_path: object,
        result: object | None,
    ) -> None:
        pct = completed * 100 // total if total else 0
        name = Path(str(file_path)).name if file_path else "?"
        status = "\u2705"
        if result is None or getattr(result, "error", None):
            status = "\u274c"
        elif getattr(result, "issues", None):
            status = f"\u26a0\ufe0f  {len(result.issues)}"
        print(f"[{completed}/{total}] ({pct}%) {name} {status}")

    def on_status(self, message: str) -> None:
        """Print a generic status message."""
        print(message)

    def on_summary(self, results: Sequence[object], total_files: int) -> None:
        total_issues = sum(len(r.issues) for r in results)
        files_with_issues = sum(1 for r in results if r.issues)
        errors = sum(1 for r in results if r.error)
        print(
            f"\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files",
            end="",
        )
        if errors:
            print(f" ({errors} errors)")
        else:
            print()
        if len(results) < total_files:
            print(f"  \u26a0\ufe0f  {total_files - len(results)} file(s) could not be scanned")

    def on_session_summary(self, session: object) -> None:
        """Print a formatted session summary (watch-mode or full scan)."""
        summary = session.get_summary()
        print(f"\n\n{'=' * 70}")
        print("\U0001f4cb SESSION SUMMARY")
        print("=" * 70)
        print(f"   Files scanned:     {summary['files_scanned']}")
        print(f"   Files with issues: {summary['files_with_issues']}")
        print(f"   Files clean:       {summary['files_clean']}")
        print(f"   Files with errors: {summary['files_error']}")
        print(f"   Total issues:      {summary['total_issues']}")
        print()
        if summary.get("issue_breakdown"):
            print("   Issue breakdown:")
            for kind, count in sorted(summary["issue_breakdown"].items(), key=lambda x: -x[1]):
                bar = "\u2588" * min(count, 30)
                print(f"      {kind:<25} {count:>4} {bar}")
        print(f"\n   \U0001f4c1 Log saved to: {session.log_file}")
        print("=" * 70)
