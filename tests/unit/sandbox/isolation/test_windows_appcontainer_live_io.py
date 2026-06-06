from pathlib import Path

import pytest

from pysymex.sandbox.errors import SandboxSetupError
from pysymex.sandbox.types import ExecutionStatus, ResourceLimits, SandboxConfig
from tests.unit.sandbox.isolation.windows_appcontainer_helpers import (
    InspectableWindowsAppContainerBackend,
    has_live_appcontainer_support,
)


class TestWindowsAppContainerBackend:
    @pytest.mark.timeout(60)
    @pytest.mark.skipif(
        not has_live_appcontainer_support(),
        reason="Windows AppContainer APIs are unavailable",
    )
    def test_live_appcontainer_accepts_large_stdin_without_pre_resume_deadlock(
        self,
        tmp_path: Path,
    ) -> None:
        backend = InspectableWindowsAppContainerBackend(
            SandboxConfig(
                limits=ResourceLimits(timeout_seconds=10, max_output_bytes=128),
            )
        )
        try:
            backend.setup()
        except SandboxSetupError as exc:
            pytest.skip(f"live AppContainer backend unavailable: {exc}")
        try:
            payload = b"x" * (1024 * 1024)
            status, exit_code, stdout, stderr, _, _ = backend.run_raw_python_for_test(
                ("import sys; data = sys.stdin.buffer.read(); print(len(data))"),
                input_data=payload,
            )
            assert status is ExecutionStatus.SUCCESS
            assert exit_code == 0
            assert stdout.strip() == str(len(payload)).encode("ascii")
            assert stderr == b""
        finally:
            backend.cleanup()

    @pytest.mark.timeout(60)
    @pytest.mark.skipif(
        not has_live_appcontainer_support(),
        reason="Windows AppContainer APIs are unavailable",
    )
    def test_live_appcontainer_denies_host_directory_reads(self, tmp_path: Path) -> None:
        host_profile = tmp_path / "host_profile"
        host_profile.mkdir()
        (host_profile / "token.txt").write_text("host token", encoding="utf-8")
        backend = InspectableWindowsAppContainerBackend(
            SandboxConfig(
                limits=ResourceLimits(timeout_seconds=10, max_output_bytes=256),
            )
        )
        try:
            backend.setup()
        except SandboxSetupError as exc:
            pytest.skip(f"live AppContainer backend unavailable: {exc}")
        try:
            status, exit_code, stdout, stderr, _, _ = backend.run_raw_python_for_test(
                (
                    "import pathlib, sys\n"
                    f"host_profile = pathlib.Path({str(host_profile)!r})\n"
                    "checks = []\n"
                    "try:\n"
                    "    list(host_profile.iterdir())\n"
                    "except Exception:\n"
                    "    checks.append('list-denied')\n"
                    "try:\n"
                    "    (host_profile / 'token.txt').read_text(encoding='utf-8')\n"
                    "except Exception:\n"
                    "    checks.append('read-denied')\n"
                    "print(','.join(sorted(checks)))\n"
                    "sys.exit(0 if len(checks) == 2 else 94)\n"
                )
            )
            assert status is ExecutionStatus.SUCCESS
            assert exit_code == 0
            assert stdout.strip() == b"list-denied,read-denied"
            assert stderr == b""
        finally:
            backend.cleanup()

    @pytest.mark.timeout(60)
    @pytest.mark.skipif(
        not has_live_appcontainer_support(),
        reason="Windows AppContainer APIs are unavailable",
    )
    def test_live_appcontainer_timeout_terminates_job(self, tmp_path: Path) -> None:
        backend = InspectableWindowsAppContainerBackend(
            SandboxConfig(
                limits=ResourceLimits(timeout_seconds=0.2, max_output_bytes=128),
            )
        )
        try:
            backend.setup()
        except SandboxSetupError as exc:
            pytest.skip(f"live AppContainer backend unavailable: {exc}")
        try:
            status, exit_code, stdout, stderr, error_message, blocked = (
                backend.run_raw_python_for_test("while True:\n    pass\n")
            )
            assert status is ExecutionStatus.TIMEOUT
            assert exit_code is None
            assert stdout == b""
            assert stderr == b""
            assert error_message is not None
            assert "timed out" in error_message
            assert blocked == ()
        finally:
            backend.cleanup()

    @pytest.mark.timeout(60)
    @pytest.mark.skipif(
        not has_live_appcontainer_support(),
        reason="Windows AppContainer APIs are unavailable",
    )
    def test_live_appcontainer_reports_output_limit_violation(self, tmp_path: Path) -> None:
        backend = InspectableWindowsAppContainerBackend(
            SandboxConfig(
                limits=ResourceLimits(timeout_seconds=10, max_output_bytes=16),
            )
        )
        try:
            backend.setup()
        except SandboxSetupError as exc:
            pytest.skip(f"live AppContainer backend unavailable: {exc}")
        try:
            status, exit_code, stdout, stderr, error_message, blocked = (
                backend.run_raw_python_for_test("print('x' * 256)")
            )
            assert status is ExecutionStatus.SECURITY_VIOLATION
            assert exit_code == 0
            assert len(stdout) == 16
            assert stderr == b""
            assert error_message is not None
            assert "output exceeded" in error_message
            assert blocked == ("output-limit",)
        finally:
            backend.cleanup()
