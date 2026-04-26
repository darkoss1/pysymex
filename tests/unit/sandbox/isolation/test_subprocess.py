import pytest
from pysymex.sandbox.errors import SandboxSetupError
from pysymex.sandbox.isolation.subprocess import SubprocessBackend
from pysymex.sandbox.types import ExecutionStatus, ResourceLimits, SandboxConfig


class TestSubprocessBackend:
    """Test suite for pysymex.sandbox.isolation.subprocess.SubprocessBackend."""

    @pytest.mark.timeout(30)
    def test_is_available(self) -> None:
        """Test is_available behavior."""
        backend = SubprocessBackend(SandboxConfig())
        assert backend.is_available is True

    @pytest.mark.timeout(30)
    def test_get_capabilities(self) -> None:
        """Test get_capabilities behavior."""
        backend = SubprocessBackend(SandboxConfig())
        caps = backend.get_capabilities()
        assert caps.process_isolation is True
        assert caps.filesystem_jail is True
        assert caps.network_blocking is False
        assert caps.syscall_filtering is False

    @pytest.mark.timeout(30)
    def test_setup(self) -> None:
        """Test setup behavior."""
        backend = SubprocessBackend(SandboxConfig())
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
        backend = SubprocessBackend(SandboxConfig())
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
        backend = SubprocessBackend(SandboxConfig())
        try:
            backend.setup()
            result = backend.execute(
                b"print('hello from subprocess')\n",
                "target.py",
                b"",
                {},
            )
            assert result.status is ExecutionStatus.SUCCESS
            assert result.exit_code == 0
            assert "hello from subprocess" in result.get_stdout_text()
        finally:
            backend.cleanup()

    @pytest.mark.timeout(30)
    def test_execute_without_setup_fails(self) -> None:
        """Execution must fail closed when backend setup has not been completed."""
        backend = SubprocessBackend(SandboxConfig())
        with pytest.raises(SandboxSetupError):
            backend.execute(b"print('x')", "target.py", b"", {})

    @pytest.mark.timeout(30)
    def test_network_blocked(self) -> None:
        """Prevents outbound network pivot attempts from sandboxed code."""
        backend = SubprocessBackend(SandboxConfig())
        try:
            backend.setup()
            code = b"import socket\ns = socket.socket()\ns.connect(('example.com', 80))\n"
            result = backend.execute(code, "net_block.py", b"", {})
            assert result.status is ExecutionStatus.FAILED
            assert result.exit_code is not None and result.exit_code != 0
            stderr_text = result.get_stderr_text()
            assert (
                "network access is hard-blocked" in stderr_text
                or "sandbox-harness: rejected" in stderr_text
                or "blocked runtime event" in stderr_text
            )
        finally:
            backend.cleanup()

    @pytest.mark.timeout(30)
    def test_filesystem_write_blocked(self) -> None:
        """Prevents writes outside the jail to block host filesystem tampering."""
        config = SandboxConfig(harness_restrict_builtins=False)
        backend = SubprocessBackend(config)
        try:
            backend.setup()
            code = b"open('/tmp/pysymex_escape.txt', 'w').write('x')\n"
            result = backend.execute(code, "fs_block.py", b"", {})
            assert result.status is ExecutionStatus.FAILED
            assert result.exit_code is not None and result.exit_code != 0
            assert "blocked write" in result.get_stderr_text()
        finally:
            backend.cleanup()

    @pytest.mark.timeout(30)
    def test_subprocess_blocked(self) -> None:
        """Prevents process-spawn attempts that could escape sandbox constraints."""
        backend = SubprocessBackend(SandboxConfig())
        try:
            backend.setup()
            code = b"import subprocess\nsubprocess.run(['python', '-V'])\n"
            result = backend.execute(code, "proc_block.py", b"", {})
            assert result.status is ExecutionStatus.FAILED
            assert result.exit_code is not None and result.exit_code != 0
            stderr_text = result.get_stderr_text()
            assert (
                "sandbox-harness: rejected" in stderr_text or "blocked runtime event" in stderr_text
            )
        finally:
            backend.cleanup()

    @pytest.mark.timeout(30)
    def test_forbidden_import_blocked(self) -> None:
        """Blocks forbidden imports to stop direct access to sensitive host APIs."""
        backend = SubprocessBackend(SandboxConfig())
        try:
            backend.setup()
            result = backend.execute(b"import os\n", "blocked_import.py", b"", {})
            assert result.status is ExecutionStatus.FAILED
            assert result.exit_code is not None and result.exit_code != 0
            assert "sandbox-harness: rejected" in result.get_stderr_text()
        finally:
            backend.cleanup()

    @pytest.mark.timeout(30)
    def test_permitted_operation_succeeds(self) -> None:
        """Allows harmless deterministic code to complete under sandbox restrictions."""
        config = SandboxConfig(
            harness_restrict_builtins=False,
            limits=ResourceLimits(timeout_seconds=5.0, memory_mb=64, cpu_seconds=5),
        )
        backend = SubprocessBackend(config)
        try:
            backend.setup()
            code = (
                b"with open('inside_jail.txt', 'w', encoding='utf-8') as f:\n"
                b"    f.write('ok')\n"
                b"print('safe done')\n"
            )
            result = backend.execute(code, "allowed.py", b"", {})
            assert result.status is ExecutionStatus.SUCCESS
            assert result.exit_code == 0
            assert "safe done" in result.get_stdout_text()
        finally:
            backend.cleanup()

    @pytest.mark.timeout(30)
    def test_graceful_degradation(self) -> None:
        """Ensures fallback backend executes safely even without strong OS-level hardening."""
        backend = SubprocessBackend(SandboxConfig())
        try:
            backend.setup()
            caps = backend.get_capabilities()
            assert caps.network_blocking is False
            assert caps.syscall_filtering is False
            result = backend.execute(b"print('fallback works')\n", "fallback.py", b"", {})
            assert result.status is ExecutionStatus.SUCCESS
            assert "fallback works" in result.get_stdout_text()
        finally:
            backend.cleanup()
