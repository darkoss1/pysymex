from collections.abc import Sequence

from pysymex.analysis.detectors.protocols import (
    ExecutionContextLike,
    ScanReporter,
)


class TestScanReporter:
    """Test suite for pysymex.analysis.detectors.protocols.ScanReporter."""

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


class TestExecutionContextLike:
    """Test suite for pysymex.analysis.detectors.protocols.ExecutionContextLike."""

    def test_execution_context_like_is_detector_owned_structural_protocol(self) -> None:
        """Analysis owns the structural view and does not import execution runtime."""

        class ExecutorView:
            instructions: Sequence[object] = ()
            solver = object()
            _paths_explored = 0
            _coverage: set[int] = set()
            issues: Sequence[object] = ()

            def register_hook(self, hook_name: str, handler: object) -> None:
                _ = hook_name, handler

        assert isinstance(ExecutorView(), ExecutionContextLike)
