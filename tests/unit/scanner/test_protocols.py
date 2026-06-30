from collections.abc import Sequence

from pysymex._internal.scanner.protocols import ScanReporter


class TestScanReporter:
    """Test suite for pysymex._internal.scanner.protocols.ScanReporter."""

    def test_structural_reporter_methods(self) -> None:
        """ScanReporter remains a structural protocol for scanner callbacks."""

        class Reporter:
            def __init__(self) -> None:
                self.events: list[str] = []

            def on_status(self, message: str) -> None:
                self.events.append(f"status:{message}")

            def on_issue(self, issue: dict[str, object]) -> None:
                self.events.append(f"issue:{issue['kind']}")

            def on_error(self, file_path: object, error: str) -> None:
                self.events.append(f"error:{file_path}:{error}")

            def on_progress(
                self,
                completed: int,
                total: int,
                file_path: object,
                result: object | None,
            ) -> None:
                _ = result
                self.events.append(f"progress:{completed}/{total}:{file_path}")

            def on_summary(self, results: Sequence[object], total_files: int) -> None:
                self.events.append(f"summary:{len(results)}/{total_files}")

        reporter: ScanReporter = Reporter()
        reporter.on_status("running")
        reporter.on_issue({"kind": "DEAD_CODE"})
        reporter.on_error("x.py", "failed")
        reporter.on_progress(1, 2, "x.py", None)
        reporter.on_summary([], 2)

        assert isinstance(reporter, Reporter)
        assert reporter.events == [
            "status:running",
            "issue:DEAD_CODE",
            "error:x.py:failed",
            "progress:1/2:x.py",
            "summary:0/2",
        ]
