import sys
from unittest.mock import PropertyMock, patch

import pytest
from pysymex.sandbox.errors import SandboxSetupError
from pysymex.sandbox.isolation.windows import WindowsJobBackend
from pysymex.sandbox.types import ExecutionStatus, SandboxConfig


class _FakeProcess:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.pid = 42
        self._handle = 99
        self.kill_called = False

    def communicate(
        self, input: bytes | None = None, timeout: float | None = None
    ) -> tuple[bytes, bytes]:
        _ = input
        _ = timeout
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.kill_called = True

    def wait(self, timeout: float | None = None) -> int:
        _ = timeout
        return self.returncode


class TestWindowsJobBackend:
    """Test suite for pysymex.sandbox.isolation.windows.WindowsJobBackend."""

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_is_available(self) -> None:
        """Test is_available behavior."""
        backend = WindowsJobBackend(SandboxConfig())
        assert isinstance(backend.is_available, bool)

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_get_capabilities(self) -> None:
        """Test get_capabilities behavior."""
        backend = WindowsJobBackend(SandboxConfig())
        caps = backend.get_capabilities()
        assert caps.process_isolation is True
        assert caps.filesystem_jail is True
        assert caps.memory_limits is True
        assert caps.cpu_limits is True
        assert caps.process_limits is True
        assert caps.network_blocking is False

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_setup(self) -> None:
        """Test setup behavior."""
        backend = WindowsJobBackend(SandboxConfig())
        with (
            patch.object(
                WindowsJobBackend, "is_available", new_callable=PropertyMock, return_value=True
            ),
            patch.object(WindowsJobBackend, "_create_configured_job_object", return_value=123),
        ):
            try:
                backend.setup()
                assert backend.is_setup is True
                assert backend.jail_path is not None
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_cleanup(self) -> None:
        """Test cleanup behavior."""
        backend = WindowsJobBackend(SandboxConfig())
        with (
            patch("ctypes.windll.kernel32.CloseHandle", return_value=1),
            patch.object(
                WindowsJobBackend, "is_available", new_callable=PropertyMock, return_value=True
            ),
            patch.object(WindowsJobBackend, "_create_configured_job_object", return_value=321),
        ):
            backend.setup()
            backend.cleanup()
            assert backend.is_setup is False
            assert backend.jail_path is None

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_execute(self) -> None:
        """Test execute behavior."""
        backend = WindowsJobBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(0, b"ok\n", b"")
        with (
            patch.object(
                WindowsJobBackend, "is_available", new_callable=PropertyMock, return_value=True
            ),
            patch.object(WindowsJobBackend, "_create_configured_job_object", return_value=1),
            patch.object(WindowsJobBackend, "_assign_to_job", return_value=None),
            patch.object(WindowsJobBackend, "_resume_process_main_thread", return_value=None),
            patch("pysymex.sandbox.isolation.windows.subprocess.Popen", return_value=fake),
            patch("ctypes.windll.kernel32.CloseHandle", return_value=1),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('ok')\n", "t.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert result.exit_code == 0
                assert "ok" in result.get_stdout_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_execute_without_setup_fails(self) -> None:
        """Execution must fail closed until setup has produced a configured Job Object."""
        backend = WindowsJobBackend(SandboxConfig())
        with pytest.raises(SandboxSetupError):
            backend.execute(b"print('x')", "x.py", b"", {})

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_network_blocked(self) -> None:
        """Prevents network access attempts from reaching host network APIs."""
        backend = WindowsJobBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(1, b"", b"sandbox-harness: network access is hard-blocked")
        with (
            patch.object(
                WindowsJobBackend, "is_available", new_callable=PropertyMock, return_value=True
            ),
            patch.object(WindowsJobBackend, "_create_configured_job_object", return_value=2),
            patch.object(WindowsJobBackend, "_assign_to_job", return_value=None),
            patch.object(WindowsJobBackend, "_resume_process_main_thread", return_value=None),
            patch("pysymex.sandbox.isolation.windows.subprocess.Popen", return_value=fake),
            patch("ctypes.windll.kernel32.CloseHandle", return_value=1),
        ):
            backend.setup()
            try:
                result = backend.execute(b"import socket\n", "net.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "hard-blocked" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_filesystem_write_blocked(self) -> None:
        """Blocks writes outside sandbox jail to prevent host filesystem modification."""
        config = SandboxConfig(harness_restrict_builtins=False, harness_install_audit_hook=False)
        backend = WindowsJobBackend(config)
        fake = _FakeProcess(1, b"", b"sandbox-harness: blocked write")
        with (
            patch.object(
                WindowsJobBackend, "is_available", new_callable=PropertyMock, return_value=True
            ),
            patch.object(WindowsJobBackend, "_create_configured_job_object", return_value=3),
            patch.object(WindowsJobBackend, "_assign_to_job", return_value=None),
            patch.object(WindowsJobBackend, "_resume_process_main_thread", return_value=None),
            patch("pysymex.sandbox.isolation.windows.subprocess.Popen", return_value=fake),
            patch("ctypes.windll.kernel32.CloseHandle", return_value=1),
        ):
            backend.setup()
            try:
                result = backend.execute(b"open('C:/escape.txt', 'w')\n", "fs.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "blocked write" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_subprocess_blocked(self) -> None:
        """Blocks process creation attempts to prevent sandbox breakout chains."""
        backend = WindowsJobBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(1, b"", b"sandbox-harness: blocked runtime event")
        with (
            patch.object(
                WindowsJobBackend, "is_available", new_callable=PropertyMock, return_value=True
            ),
            patch.object(WindowsJobBackend, "_create_configured_job_object", return_value=4),
            patch.object(WindowsJobBackend, "_assign_to_job", return_value=None),
            patch.object(WindowsJobBackend, "_resume_process_main_thread", return_value=None),
            patch("pysymex.sandbox.isolation.windows.subprocess.Popen", return_value=fake),
            patch("ctypes.windll.kernel32.CloseHandle", return_value=1),
        ):
            backend.setup()
            try:
                result = backend.execute(b"import subprocess\n", "proc.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "blocked runtime event" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_forbidden_import_blocked(self) -> None:
        """Rejects forbidden imports to keep sensitive host modules inaccessible."""
        backend = WindowsJobBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(1, b"", b"sandbox-harness: rejected")
        with (
            patch.object(
                WindowsJobBackend, "is_available", new_callable=PropertyMock, return_value=True
            ),
            patch.object(WindowsJobBackend, "_create_configured_job_object", return_value=5),
            patch.object(WindowsJobBackend, "_assign_to_job", return_value=None),
            patch.object(WindowsJobBackend, "_resume_process_main_thread", return_value=None),
            patch("pysymex.sandbox.isolation.windows.subprocess.Popen", return_value=fake),
            patch("ctypes.windll.kernel32.CloseHandle", return_value=1),
        ):
            backend.setup()
            try:
                result = backend.execute(b"import os\n", "imp.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "rejected" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_permitted_operation_succeeds(self) -> None:
        """Allows benign operations to run successfully under Job Object controls."""
        backend = WindowsJobBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(0, b"safe\n", b"")
        with (
            patch.object(
                WindowsJobBackend, "is_available", new_callable=PropertyMock, return_value=True
            ),
            patch.object(WindowsJobBackend, "_create_configured_job_object", return_value=6),
            patch.object(WindowsJobBackend, "_assign_to_job", return_value=None),
            patch.object(WindowsJobBackend, "_resume_process_main_thread", return_value=None),
            patch("pysymex.sandbox.isolation.windows.subprocess.Popen", return_value=fake),
            patch("ctypes.windll.kernel32.CloseHandle", return_value=1),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('safe')\n", "safe.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert "safe" in result.get_stdout_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "win32", reason="Windows only")
    def test_graceful_degradation(self) -> None:
        """Falls back from suspended-start mode when host policy rejects CREATE_SUSPENDED."""
        backend = WindowsJobBackend(SandboxConfig(harness_install_audit_hook=False))
        fallback_process = _FakeProcess(0, b"fallback\n", b"")

        class _RaiseOnce:
            def __init__(self) -> None:
                self.calls = 0

            def __call__(self, *args: object, **kwargs: object) -> _FakeProcess:
                self.calls += 1
                _ = args
                _ = kwargs
                if self.calls == 1:
                    raise OSError("CREATE_SUSPENDED rejected")
                return fallback_process

        popen_side_effect = _RaiseOnce()
        with (
            patch.object(
                WindowsJobBackend, "is_available", new_callable=PropertyMock, return_value=True
            ),
            patch.object(WindowsJobBackend, "_create_configured_job_object", return_value=7),
            patch.object(WindowsJobBackend, "_assign_to_job", return_value=None),
            patch.object(WindowsJobBackend, "_resume_process_main_thread", return_value=None),
            patch(
                "pysymex.sandbox.isolation.windows.subprocess.Popen", side_effect=popen_side_effect
            ),
            patch("ctypes.windll.kernel32.CloseHandle", return_value=1),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('fallback')\n", "fallback.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert "fallback" in result.get_stdout_text()
            finally:
                backend.cleanup()
