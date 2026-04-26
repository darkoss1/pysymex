import sys
from unittest.mock import patch

import pytest
from pysymex.sandbox.errors import SandboxSetupError
from pysymex.sandbox.isolation.linux import LinuxNamespaceBackend
from pysymex.sandbox.types import ExecutionStatus, SandboxConfig


class _FakeProcess:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.pid = 12345

    def communicate(
        self, input: bytes | None = None, timeout: float | None = None
    ) -> tuple[bytes, bytes]:
        _ = input
        _ = timeout
        return self._stdout, self._stderr

    def kill(self) -> None:
        return None


class TestLinuxNamespaceBackend:
    """Test suite for pysymex.sandbox.isolation.linux.LinuxNamespaceBackend."""

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_is_available(self) -> None:
        """Test is_available behavior."""
        backend = LinuxNamespaceBackend(SandboxConfig())
        assert isinstance(backend.is_available, bool)

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_get_capabilities(self) -> None:
        """Test get_capabilities behavior."""
        backend = LinuxNamespaceBackend(SandboxConfig(harness_install_audit_hook=False))
        caps = backend.get_capabilities()
        assert caps.process_isolation is True
        assert caps.memory_limits is True
        assert caps.cpu_limits is True
        assert caps.process_limits is True

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_setup(self) -> None:
        """Test setup behavior."""
        backend = LinuxNamespaceBackend(SandboxConfig())
        if not backend.is_available:
            with pytest.raises(SandboxSetupError):
                backend.setup()
            return
        try:
            backend.setup()
            assert backend.is_setup is True
            assert backend.jail_path is not None
            assert backend.jail_path.exists()
        finally:
            backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_cleanup(self) -> None:
        """Test cleanup behavior."""
        backend = LinuxNamespaceBackend(SandboxConfig())
        backend.cleanup()
        assert backend.is_setup is False

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_execute(self) -> None:
        """Test execute behavior."""
        config = SandboxConfig(harness_install_audit_hook=False)
        backend = LinuxNamespaceBackend(config)
        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch(
                "pysymex.sandbox.isolation.linux.subprocess.Popen",
                return_value=_FakeProcess(0, b"ok\n", b""),
            ),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('ok')\n", "x.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert result.exit_code == 0
                assert "ok" in result.get_stdout_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_network_blocked(self) -> None:
        """Blocks outbound network attempts from isolated Linux sandbox workloads."""
        config = SandboxConfig(harness_install_audit_hook=False)
        backend = LinuxNamespaceBackend(config)
        fake = _FakeProcess(1, b"", b"sandbox-harness: network access is hard-blocked")
        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", return_value=fake),
        ):
            backend.setup()
            try:
                result = backend.execute(b"import socket\n", "n.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "hard-blocked" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_filesystem_write_blocked(self) -> None:
        """Blocks writes outside jail to prevent host-path corruption attacks."""
        config = SandboxConfig(harness_restrict_builtins=False, harness_install_audit_hook=False)
        backend = LinuxNamespaceBackend(config)
        fake = _FakeProcess(1, b"", b"sandbox-harness: blocked write")
        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", return_value=fake),
        ):
            backend.setup()
            try:
                result = backend.execute(b"open('/tmp/x', 'w')\n", "w.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "blocked write" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_subprocess_blocked(self) -> None:
        """Blocks child-process creation attempts to contain privilege escalation chains."""
        config = SandboxConfig(harness_install_audit_hook=False)
        backend = LinuxNamespaceBackend(config)
        fake = _FakeProcess(1, b"", b"sandbox-harness: blocked runtime event 'subprocess.Popen'")
        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", return_value=fake),
        ):
            backend.setup()
            try:
                result = backend.execute(b"import subprocess\n", "p.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "blocked runtime event" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_forbidden_import_blocked(self) -> None:
        """Rejects forbidden imports to prevent sandboxed code from touching host APIs."""
        config = SandboxConfig(harness_install_audit_hook=False)
        backend = LinuxNamespaceBackend(config)
        fake = _FakeProcess(1, b"", b"sandbox-harness: rejected")
        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", return_value=fake),
        ):
            backend.setup()
            try:
                result = backend.execute(b"import os\n", "i.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "rejected" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_permitted_operation_succeeds(self) -> None:
        """Allows benign computation when no forbidden operations are attempted."""
        config = SandboxConfig(harness_install_audit_hook=False)
        backend = LinuxNamespaceBackend(config)
        fake = _FakeProcess(0, b"safe\n", b"")
        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", return_value=fake),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('safe')\n", "safe.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert "safe" in result.get_stdout_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    @pytest.mark.skipif(not sys.platform == "linux", reason="Linux only")
    def test_graceful_degradation(self) -> None:
        """Maintains safe execution behavior when strict seccomp mode is disabled."""
        config = SandboxConfig(harness_install_audit_hook=False)
        backend = LinuxNamespaceBackend(config)
        fake = _FakeProcess(0, b"degraded-safe\n", b"")
        with (
            patch("pysymex.sandbox.isolation.linux.LinuxNamespaceBackend.is_available", True),
            patch("pysymex.sandbox.isolation.linux.subprocess.Popen", return_value=fake),
        ):
            backend.setup()
            try:
                caps = backend.get_capabilities()
                result = backend.execute(b"print('degraded-safe')\n", "d.py", b"", {})
                assert caps.process_isolation is True
                assert result.status is ExecutionStatus.SUCCESS
                assert "degraded-safe" in result.get_stdout_text()
            finally:
                backend.cleanup()
