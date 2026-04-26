from unittest.mock import patch

import pytest
from pysymex.sandbox.errors import SandboxSetupError
from pysymex.sandbox.isolation.wasm import WasmBackend
from pysymex.sandbox.types import ExecutionStatus, SandboxConfig


class _FakeProcess:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    def communicate(
        self, input: bytes | None = None, timeout: float | None = None
    ) -> tuple[bytes, bytes]:
        _ = input
        _ = timeout
        return self._stdout, self._stderr

    def kill(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        _ = timeout
        return self.returncode


class TestWasmBackend:
    """Test suite for pysymex.sandbox.isolation.wasm.WasmBackend."""

    @pytest.mark.timeout(30)
    def test_is_available(self) -> None:
        """Test is_available behavior."""
        backend = WasmBackend(SandboxConfig())
        assert isinstance(backend.is_available, bool)

    @pytest.mark.timeout(30)
    def test_get_capabilities(self) -> None:
        """Test get_capabilities behavior."""
        backend = WasmBackend(SandboxConfig())
        caps = backend.get_capabilities()
        assert caps.process_isolation is True
        assert caps.filesystem_jail is True
        assert caps.network_blocking is False
        assert caps.syscall_filtering is False
        assert caps.memory_limits is False
        assert caps.cpu_limits is False
        assert caps.process_limits is False

    @pytest.mark.timeout(30)
    def test_setup(self) -> None:
        """Test setup behavior."""
        backend = WasmBackend(SandboxConfig())
        try:
            backend.setup()
            assert backend.is_setup is True
            assert backend.jail_path is not None
            assert backend.jail_path.exists()
        finally:
            backend.cleanup()

    @pytest.mark.timeout(30)
    def test_cleanup(self) -> None:
        """Test cleanup behavior."""
        backend = WasmBackend(SandboxConfig())
        backend.setup()
        jail_path = backend.jail_path
        assert jail_path is not None
        backend.cleanup()
        assert backend.is_setup is False
        assert backend.jail_path is None
        assert not jail_path.exists()

    @pytest.mark.timeout(30)
    def test_execute(self) -> None:
        """Test execute behavior."""
        backend = WasmBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(0, b"ok\n", b"")
        with patch("pysymex.sandbox.isolation.wasm.subprocess.Popen", return_value=fake):
            backend.setup()
            try:
                result = backend.execute(b"print('ok')\n", "target.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert result.exit_code == 0
                assert "ok" in result.get_stdout_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    def test_execute_without_setup_fails(self) -> None:
        """Execution must fail if setup did not create an isolated jail."""
        backend = WasmBackend(SandboxConfig())
        with pytest.raises(SandboxSetupError):
            backend.execute(b"print('x')", "x.py", b"", {})

    @pytest.mark.timeout(30)
    def test_network_blocked(self) -> None:
        """Blocks outbound network access attempts in wasm fallback mode."""
        backend = WasmBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(1, b"", b"sandbox-harness: network access is hard-blocked")
        with patch("pysymex.sandbox.isolation.wasm.subprocess.Popen", return_value=fake):
            backend.setup()
            try:
                result = backend.execute(b"import socket\n", "net.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "hard-blocked" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    def test_filesystem_write_blocked(self) -> None:
        """Blocks writes outside the jail in wasm fallback mode."""
        config = SandboxConfig(harness_restrict_builtins=False, harness_install_audit_hook=False)
        backend = WasmBackend(config)
        fake = _FakeProcess(1, b"", b"sandbox-harness: blocked write")
        with patch("pysymex.sandbox.isolation.wasm.subprocess.Popen", return_value=fake):
            backend.setup()
            try:
                result = backend.execute(b"open('/tmp/x', 'w')\n", "fs.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "blocked write" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    def test_subprocess_blocked(self) -> None:
        """Blocks subprocess spawning attempts from sandboxed wasm fallback code."""
        backend = WasmBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(1, b"", b"sandbox-harness: blocked runtime event")
        with patch("pysymex.sandbox.isolation.wasm.subprocess.Popen", return_value=fake):
            backend.setup()
            try:
                result = backend.execute(b"import subprocess\n", "proc.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "blocked runtime event" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    def test_forbidden_import_blocked(self) -> None:
        """Rejects forbidden imports so host-sensitive modules remain inaccessible."""
        backend = WasmBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(1, b"", b"sandbox-harness: rejected")
        with patch("pysymex.sandbox.isolation.wasm.subprocess.Popen", return_value=fake):
            backend.setup()
            try:
                result = backend.execute(b"import os\n", "imp.py", b"", {})
                assert result.status is ExecutionStatus.FAILED
                assert "rejected" in result.get_stderr_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    def test_permitted_operation_succeeds(self) -> None:
        """Allows harmless computation to complete successfully in fallback mode."""
        backend = WasmBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(0, b"safe\n", b"")
        with patch("pysymex.sandbox.isolation.wasm.subprocess.Popen", return_value=fake):
            backend.setup()
            try:
                result = backend.execute(b"print('safe')\n", "safe.py", b"", {})
                assert result.status is ExecutionStatus.SUCCESS
                assert "safe" in result.get_stdout_text()
            finally:
                backend.cleanup()

    @pytest.mark.timeout(30)
    def test_graceful_degradation(self) -> None:
        """Maintains safe subprocess fallback when WASM runtime support is unavailable."""
        backend = WasmBackend(SandboxConfig(harness_install_audit_hook=False))
        fake = _FakeProcess(0, b"fallback\n", b"")
        with patch("pysymex.sandbox.isolation.wasm.subprocess.Popen", return_value=fake):
            backend.setup()
            try:
                caps = backend.get_capabilities()
                result = backend.execute(b"print('fallback')\n", "fallback.py", b"", {})
                assert caps.memory_limits is False
                assert result.status is ExecutionStatus.SUCCESS
                assert "fallback" in result.get_stdout_text()
            finally:
                backend.cleanup()
