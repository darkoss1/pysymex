"""Self-scan metrics harness for pysymex v0.5.0.

Runs pysymex on its own source code and asserts detection quality metrics
are within acceptable targets.

Marked with @pytest.mark.slow so it doesn't run in every CI pass.
"""

import os

import pytest


from pysymex.analysis.pipeline import Scanner, ScannerConfig

_ANALYSIS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "pysymex",
    "analysis",
)


@pytest.mark.slow
class TestSelfScanMetrics:
    """Self-scan metrics: run pysymex on its own source."""

    def test_self_scan_no_crashes(self):
        """Scanner should complete on its own source without exceptions."""

        scanner = Scanner(
            ScannerConfig(
                suppress_likely_false_positives=True,
                verbose=False,
            )
        )

        issues = scanner.scan_directory(_ANALYSIS_DIR)

        assert isinstance(issues, list)

    def test_self_scan_fp_count_under_target(self):
        """Unsuppressed issues should be under the regression threshold.

        v0.5.0: FP reduction brought unsuppressed count from ~3,000 to ~287
        (v0.4.0) to ~46 (v0.5.0).  The remaining findings are largely true
        positives (actual unused variables and genuine code quality issues).
        The threshold of 50 matches the ROADMAP v0.5.0 target.
        """

        scanner = Scanner(
            ScannerConfig(
                suppress_likely_false_positives=True,
                verbose=False,
            )
        )

        issues = scanner.scan_directory(_ANALYSIS_DIR)

        active = [i for i in issues if not i.is_suppressed()]

        assert len(active) < 50, (
            f"Expected < 50 unsuppressed issues, got {len(active)}. "
            f"Breakdown by kind: {_count_by_kind(active)}"
        )

    def test_self_scan_report_generation(self):
        """Report generation should work on self-scan results."""

        scanner = Scanner(
            ScannerConfig(
                suppress_likely_false_positives=True,
                verbose=False,
            )
        )

        issues = scanner.scan_directory(_ANALYSIS_DIR)

        text_report = scanner.generate_report(issues, format="text")

        assert "pysymex Enhanced Scan Report" in text_report

        import json

        json_report = scanner.generate_report(issues, format="json")

        data = json.loads(json_report)

        assert "issues" in data

        assert "stats" in data


def _count_by_kind(issues):
    """Count issues by kind for diagnostic output."""

    counts = {}

    for issue in issues:
        counts[issue.kind] = counts.get(issue.kind, 0) + 1

    return dict(sorted(counts.items(), key=lambda x: -x[1]))
