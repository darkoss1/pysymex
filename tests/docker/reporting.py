"""Result reporting for the Docker test runner."""

from __future__ import annotations

import sys

from tests.docker.models import TestResult, TestStatus
from tests.docker.protocols import DockerRunnerState


class DockerReportingMixin(DockerRunnerState):
    """Formatted Docker pytest result reporting methods."""

    def print_results(self, results: dict[str, TestResult]) -> int:
        """Print formatted test results."""
        print("=" * 80)
        print("DOCKER TEST RESULTS")
        print("=" * 80)
        print()
        check_symbol = "OK"
        fail_symbol = "FAIL"
        encoding = sys.stdout.encoding or "utf-8"
        try:
            check_symbol.encode(encoding)
            fail_symbol.encode(encoding)
        except UnicodeEncodeError:
            check_symbol = "OK"
            fail_symbol = "X"
        for version in sorted(results.keys()):
            result = results[version]
            status_symbol = check_symbol if result.status == TestStatus.SUCCESS else fail_symbol
            status_color = "\033[92m" if result.status == TestStatus.SUCCESS else "\033[91m"
            reset_color = "\033[0m"

            print(
                f"{status_color}{status_symbol} Python {version}{reset_color} ({result.container_name})"
            )
            print(f"  Status: {result.status.value}")
            print(f"  Duration: {result.duration:.2f}s")
            print(f"  Tests: {result.total} total")
            print(f"    Passed: {result.passed}")
            print(f"    Failed: {result.failed}")
            print(f"    Errors: {result.errors}")
            print(f"    Skipped: {result.skipped}")
            print(f"    XFailed: {result.xfailed}")
            print(f"    XPassed: {result.xpassed}")

            if result.status != TestStatus.SUCCESS:
                if result.error_output:
                    print(f"  Error:\n{result.error_output}")
                if result.output:
                    print(f"  Output:\n{result.output}")

            print()

        return self._print_summary(results, check_symbol, fail_symbol)

    def _print_summary(
        self,
        results: dict[str, TestResult],
        check_symbol: str,
        fail_symbol: str,
    ) -> int:
        """Print aggregate Docker test result summary."""
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)

        total_passed = sum(r.passed for r in results.values())
        total_failed = sum(r.failed for r in results.values())
        total_errors = sum(r.errors for r in results.values())
        total_skipped = sum(r.skipped for r in results.values())
        total_xfailed = sum(r.xfailed for r in results.values())
        total_xpassed = sum(r.xpassed for r in results.values())
        total_tests = sum(r.total for r in results.values())

        print(f"Total tests across all versions: {total_tests}")
        print(f"  Passed: {total_passed}")
        print(f"  Failed: {total_failed}")
        print(f"  Errors: {total_errors}")
        print(f"  Skipped: {total_skipped}")
        print(f"  XFailed: {total_xfailed}")
        print(f"  XPassed: {total_xpassed}")
        print()

        successful_versions = sum(1 for r in results.values() if r.status == TestStatus.SUCCESS)
        print(f"Successful Python versions: {successful_versions}/{len(results)}")

        if successful_versions == len(results):
            print(f"\n{check_symbol} All tests passed across all Python versions!")
            return 0
        print(f"\n{fail_symbol} Some tests failed. See details above.")
        return 1
