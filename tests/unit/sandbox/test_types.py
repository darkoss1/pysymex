from dataclasses import FrozenInstanceError, asdict

import pytest

from pysymex.sandbox.types import (
    ExecutionStatus,
    ResourceLimits,
    SandboxBackend,
    SandboxConfig,
    SandboxResult,
    SecurityCapabilities,
)


class TestSandboxBackend:
    """Test suite for pysymex.sandbox.types.SandboxBackend."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert SandboxBackend.LINUX_NAMESPACE.name == "LINUX_NAMESPACE"
        assert SandboxBackend.WINDOWS_JOB.name == "WINDOWS_JOB"
        assert SandboxBackend.WASM.name == "WASM"
        assert SandboxBackend.SUBPROCESS.name == "SUBPROCESS"


class TestExecutionStatus:
    """Test suite for pysymex.sandbox.types.ExecutionStatus."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ExecutionStatus.SUCCESS.name == "SUCCESS"
        assert ExecutionStatus.FAILED.name == "FAILED"
        assert ExecutionStatus.TIMEOUT.name == "TIMEOUT"
        assert ExecutionStatus.MEMORY_EXCEEDED.name == "MEMORY_EXCEEDED"
        assert ExecutionStatus.CPU_EXCEEDED.name == "CPU_EXCEEDED"
        assert ExecutionStatus.SECURITY_VIOLATION.name == "SECURITY_VIOLATION"
        assert ExecutionStatus.CRASH.name == "CRASH"
        assert ExecutionStatus.SETUP_ERROR.name == "SETUP_ERROR"


class TestSecurityCapabilities:
    """Test suite for pysymex.sandbox.types.SecurityCapabilities."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        caps = SecurityCapabilities()
        assert caps.process_isolation is False
        assert caps.filesystem_jail is False
        assert caps.network_blocking is False
        assert caps.syscall_filtering is False
        assert caps.memory_limits is False
        assert caps.cpu_limits is False
        assert caps.process_limits is False

    @pytest.mark.timeout(30)
    def test_initialization_with_enforced_capabilities(self) -> None:
        """Explicit capabilities should reflect enforced backend protections."""
        caps = SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=True,
            network_blocking=True,
            syscall_filtering=True,
            memory_limits=True,
            cpu_limits=True,
            process_limits=True,
        )
        assert caps.process_isolation is True
        assert caps.filesystem_jail is True
        assert caps.network_blocking is True
        assert caps.syscall_filtering is True
        assert caps.memory_limits is True
        assert caps.cpu_limits is True
        assert caps.process_limits is True


class TestResourceLimits:
    """Test suite for pysymex.sandbox.types.ResourceLimits."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        limits = ResourceLimits()
        assert limits.timeout_seconds == 30.0
        assert limits.cpu_seconds == 30
        assert limits.memory_mb == 256
        assert limits.max_processes == 1
        assert limits.max_file_descriptors == 32
        assert limits.max_file_size_mb == 16
        assert limits.max_output_bytes == 1024 * 1024

    @pytest.mark.timeout(30)
    def test_initialization_with_custom_values(self) -> None:
        """Custom limits should be preserved for policy tuning."""
        limits = ResourceLimits(
            timeout_seconds=2.0,
            cpu_seconds=3,
            memory_mb=64,
            max_processes=2,
            max_file_descriptors=8,
            max_file_size_mb=4,
            max_output_bytes=2048,
        )
        assert limits.timeout_seconds == 2.0
        assert limits.cpu_seconds == 3
        assert limits.memory_mb == 64
        assert limits.max_processes == 2
        assert limits.max_file_descriptors == 8
        assert limits.max_file_size_mb == 4
        assert limits.max_output_bytes == 2048


class TestSandboxConfig:
    """Test suite for pysymex.sandbox.types.SandboxConfig."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        config = SandboxConfig()
        assert isinstance(config.limits, ResourceLimits)
        assert config.backend is None
        assert config.capture_output is True
        assert config.allow_stdin is False
        assert config.allow_weak_backends is False

    @pytest.mark.timeout(30)
    def test_initialization_with_security_requirements(self) -> None:
        """Required capability policy should be retained on config creation."""
        required = SecurityCapabilities(process_isolation=True, filesystem_jail=True)
        config = SandboxConfig(required_capabilities=required)
        assert config.required_capabilities is required

    @pytest.mark.timeout(30)
    def test_initialization_forces_internal_security_flags(self) -> None:
        """Security-critical internal block flags must remain enabled even if overridden."""
        config = SandboxConfig(
            _block_network=False,
            _block_filesystem=False,
            _block_process_spawn=False,
        )
        serialized = asdict(config)
        assert serialized["_block_network"] is True
        assert serialized["_block_filesystem"] is True
        assert serialized["_block_process_spawn"] is True

    @pytest.mark.timeout(30)
    def test_initialization_is_frozen(self) -> None:
        """Sandbox config must be immutable after construction to prevent policy tampering."""
        config = SandboxConfig()
        with pytest.raises(FrozenInstanceError):
            setattr(config, "capture_output", False)


class TestSandboxResult:
    """Test suite for pysymex.sandbox.types.SandboxResult."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """All result fields should be populated exactly as provided by backend output."""
        result = SandboxResult(
            status=ExecutionStatus.FAILED,
            exit_code=9,
            stdout=b"out",
            stderr=b"err",
            wall_time_ms=7.5,
            cpu_time_ms=4.0,
            peak_memory_bytes=123,
            blocked_syscalls=["connect"],
            blocked_operations=["network"],
            error_message="failure",
            error_traceback="trace",
            output_files={"x.txt": b"data"},
        )
        assert result.status is ExecutionStatus.FAILED
        assert result.exit_code == 9
        assert result.stdout == b"out"
        assert result.stderr == b"err"
        assert result.wall_time_ms == 7.5
        assert result.cpu_time_ms == 4.0
        assert result.peak_memory_bytes == 123
        assert result.blocked_syscalls == ["connect"]
        assert result.blocked_operations == ["network"]
        assert result.error_message == "failure"
        assert result.error_traceback == "trace"
        assert result.output_files == {"x.txt": b"data"}

    @pytest.mark.timeout(30)
    def test_succeeded(self) -> None:
        """Test succeeded behavior."""
        success_result = SandboxResult(status=ExecutionStatus.SUCCESS, exit_code=0)
        failed_result = SandboxResult(status=ExecutionStatus.SUCCESS, exit_code=1)
        assert success_result.succeeded is True
        assert failed_result.succeeded is False

    @pytest.mark.timeout(30)
    def test_was_killed(self) -> None:
        """Test was_killed behavior."""
        timeout_result = SandboxResult(status=ExecutionStatus.TIMEOUT)
        security_result = SandboxResult(status=ExecutionStatus.SECURITY_VIOLATION)
        success_result = SandboxResult(status=ExecutionStatus.SUCCESS, exit_code=0)
        assert timeout_result.was_killed is True
        assert security_result.was_killed is True
        assert success_result.was_killed is False

    @pytest.mark.timeout(30)
    def test_get_stdout_text(self) -> None:
        """Test get_stdout_text behavior."""
        result = SandboxResult(status=ExecutionStatus.SUCCESS, stdout=b"hello")
        assert result.get_stdout_text() == "hello"

    @pytest.mark.timeout(30)
    def test_get_stderr_text(self) -> None:
        """Test get_stderr_text behavior."""
        result = SandboxResult(status=ExecutionStatus.SUCCESS, stderr=b"error")
        assert result.get_stderr_text() == "error"

    @pytest.mark.timeout(30)
    def test_get_combined_output(self) -> None:
        """Test get_combined_output behavior."""
        result = SandboxResult(
            status=ExecutionStatus.SUCCESS,
            stdout=b"stdout ",
            stderr=b"stderr",
        )
        assert result.get_combined_output() == "stdout stderr"
