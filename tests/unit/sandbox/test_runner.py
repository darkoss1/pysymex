from pathlib import Path

import pytest
from pysymex.sandbox.errors import SandboxError
from pysymex.sandbox.runner import SandboxRunner
from pysymex.sandbox.types import ExecutionStatus, SandboxBackend, SandboxConfig, ResourceLimits

class TestSandboxRunner:
    """Test suite for pysymex.sandbox.runner.SandboxRunner."""

    @pytest.mark.timeout(30)
    def test_is_active(self) -> None:
        """Test is_active behavior."""
        config = SandboxConfig(backend=SandboxBackend.SUBPROCESS, allow_weak_backends=True)
        runner = SandboxRunner(config)
        assert runner.is_active is False
        with runner:
            assert runner.is_active is True
        assert runner.is_active is False

    @pytest.mark.timeout(30)
    def test_backend_name(self) -> None:
        """Test backend_name behavior."""
        config = SandboxConfig(backend=SandboxBackend.SUBPROCESS, allow_weak_backends=True)
        runner = SandboxRunner(config)
        assert runner.backend_name == "none"
        with runner:
            assert runner.backend_name == "SubprocessBackend"

    @pytest.mark.timeout(30)
    def test_get_capabilities(self) -> None:
        """Test get_capabilities behavior."""
        config = SandboxConfig(backend=SandboxBackend.SUBPROCESS, allow_weak_backends=True)
        runner = SandboxRunner(config)
        before_caps = runner.get_capabilities()
        assert before_caps.process_isolation is False

        with runner:
            caps = runner.get_capabilities()
            assert caps.process_isolation is True
            assert caps.filesystem_jail is True

    @pytest.mark.timeout(30)
    def test_execute(self) -> None:
        """Test execute behavior."""
        config = SandboxConfig(
            backend=SandboxBackend.SUBPROCESS,
            allow_weak_backends=True,
            harness_install_audit_hook=False,
            limits=ResourceLimits(timeout_seconds=5.0, cpu_seconds=5, memory_mb=64),
        )
        runner = SandboxRunner(config)

        with runner:
            with pytest.raises(FileNotFoundError):
                runner.execute(Path("does_not_exist.py"))

    @pytest.mark.timeout(30)
    def test_execute_permitted_operation_succeeds(self, tmp_path: Path) -> None:
        """Permits safe code execution when no forbidden patterns are present."""
        file_path = tmp_path / "safe.py"
        file_path.write_text("print('runner-safe')\n", encoding="utf-8")

        config = SandboxConfig(
            backend=SandboxBackend.SUBPROCESS,
            allow_weak_backends=True,
            harness_install_audit_hook=False,
            limits=ResourceLimits(timeout_seconds=5.0, cpu_seconds=5, memory_mb=64),
        )
        runner = SandboxRunner(config)
        with runner:
            result = runner.execute(file_path)
            assert result.status is ExecutionStatus.SUCCESS
            assert "runner-safe" in result.get_stdout_text()

    @pytest.mark.timeout(30)
    def test_execute_forbidden_pattern_blocked(self, tmp_path: Path) -> None:
        """Blocks known escape-pattern code during pre-screen before backend execution."""
        file_path = tmp_path / "blocked.py"
        file_path.write_text("print(__globals__)\n", encoding="utf-8")

        config = SandboxConfig(backend=SandboxBackend.SUBPROCESS, allow_weak_backends=True)
        runner = SandboxRunner(config)
        with runner:
            result = runner.execute(file_path)
            assert result.status is ExecutionStatus.SECURITY_VIOLATION
            assert result.error_message is not None
            assert "pre-screening" in result.error_message

    @pytest.mark.timeout(30)
    def test_execute_code(self) -> None:
        """Test execute_code behavior."""
        config = SandboxConfig(
            backend=SandboxBackend.SUBPROCESS,
            allow_weak_backends=True,
            harness_install_audit_hook=False,
            limits=ResourceLimits(timeout_seconds=5.0, cpu_seconds=5, memory_mb=64),
        )
        runner = SandboxRunner(config)
        with runner:
            result = runner.execute_code("print('code-safe')\n", filename="safe_code.py")
            assert result.status is ExecutionStatus.SUCCESS
            assert "code-safe" in result.get_stdout_text()

            with pytest.raises(ValueError):
                runner.execute_code("print('x')", filename="../escape.py")

    @pytest.mark.timeout(30)
    def test_execute_code_inactive_runner_fails(self) -> None:
        """Execution APIs must fail closed when sandbox context is not active."""
        runner = SandboxRunner(
            SandboxConfig(backend=SandboxBackend.SUBPROCESS, allow_weak_backends=True)
        )
        with pytest.raises(SandboxError):
            runner.execute_code("print('x')")
