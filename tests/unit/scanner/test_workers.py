"""Tests for scanner worker-count planning."""

from __future__ import annotations

from unittest.mock import patch

from pysymex._internal.scanner.workers import auto_worker_count, effective_worker_count


class TestAutoWorkerCount:
    """Tests for auto worker-count selection."""

    def test_without_sandbox(self) -> None:
        """Without sandbox, the conservative cap is higher."""
        count = auto_worker_count(use_sandbox=False)
        assert 1 <= count <= 8

    def test_with_sandbox(self) -> None:
        """With sandbox, the conservative cap is lower."""
        count = auto_worker_count(use_sandbox=True)
        assert 1 <= count <= 4

    def test_with_file_count_clamps_to_useful_parallelism(self) -> None:
        """Auto worker selection avoids over-parallelizing tiny file sets."""
        count = auto_worker_count(use_sandbox=False, file_count=2)
        assert count == 1

    def test_tiny_no_sandbox_directory_stays_sequential(self) -> None:
        """Tiny trusted scans should not pay process-pool startup costs by default."""
        count = auto_worker_count(
            use_sandbox=False,
            file_count=40,
            total_source_bytes=8_000,
        )
        assert count == 1

    def test_tiny_sandbox_directory_stays_sequential_for_batch_extraction(self) -> None:
        """Tiny sandbox scans should batch bytecode extraction instead of per-file workers."""
        count = auto_worker_count(
            use_sandbox=True,
            file_count=40,
            total_source_bytes=8_000,
        )
        assert count == 1

    def test_large_no_sandbox_directory_can_parallelize(self) -> None:
        """Large trusted scans should still use workers when enough work exists."""
        with patch("pysymex._internal.scanner.workers.os.cpu_count", return_value=16):
            count = auto_worker_count(
                use_sandbox=False,
                file_count=40,
                total_source_bytes=2_000_000,
            )
        assert count > 1

    def test_with_trace_enabled_reduces_workers(self) -> None:
        """Trace-heavy scans should not increase worker count relative to baseline."""
        baseline = auto_worker_count(use_sandbox=False, file_count=100, trace_enabled=False)
        traced = auto_worker_count(use_sandbox=False, file_count=100, trace_enabled=True)
        assert traced <= baseline


class TestEffectiveWorkerCount:
    """Tests for explicit worker-count clamping."""

    def test_single_file_forces_sequential(self) -> None:
        """One file should always resolve to one worker."""
        assert effective_worker_count(1, 16) == 1

    def test_file_limited_parallelism(self) -> None:
        """Large worker counts should be clamped by useful file-level parallelism."""
        assert effective_worker_count(6, 10) == 3
