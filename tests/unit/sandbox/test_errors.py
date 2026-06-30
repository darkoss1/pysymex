import pytest

from pysymex._internal.sandbox.errors import (
    ResourceExhaustedError,
    ResourceLimitError,
    SandboxCleanupError,
    SandboxError,
    SandboxExecutionError,
    SandboxProtocolError,
    SandboxResourceError,
    SandboxSecurityError,
    SandboxSetupError,
    SandboxTimeoutError,
    SecurityError,
    SecurityViolationError,
)


class TestSandboxError:
    """Test suite for pysymex._internal.sandbox.errors.SandboxError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = SandboxError("sandbox failure")
        assert isinstance(err, Exception)
        assert str(err) == "sandbox failure"


class TestSandboxSetupError:
    """Test suite for pysymex._internal.sandbox.errors.SandboxSetupError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = SandboxSetupError("setup failed")
        assert isinstance(err, SandboxError)
        assert str(err) == "setup failed"


class TestSandboxExecutionError:
    """Test suite for pysymex._internal.sandbox.errors.SandboxExecutionError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        err = SandboxExecutionError("runtime failed")
        assert isinstance(err, SandboxError)
        assert str(err) == "runtime failed"


class TestSandboxProtocolError:
    """Test suite for pysymex._internal.sandbox.errors.SandboxProtocolError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        err = SandboxProtocolError("bad payload")
        assert isinstance(err, SandboxError)
        assert str(err) == "bad payload"


class TestSandboxResourceError:
    """Test suite for pysymex._internal.sandbox.errors.SandboxResourceError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        err = SandboxResourceError("output limit")
        assert isinstance(err, SandboxError)
        assert str(err) == "output limit"


class TestSandboxSecurityError:
    """Test suite for pysymex._internal.sandbox.errors.SandboxSecurityError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        err = SandboxSecurityError("network denied")
        assert isinstance(err, SandboxError)
        assert str(err) == "network denied"


class TestSandboxTimeoutError:
    """Test suite for pysymex._internal.sandbox.errors.SandboxTimeoutError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = SandboxTimeoutError(2.5)
        assert isinstance(err, SandboxResourceError)
        assert err.timeout_seconds == 2.5
        assert str(err) == "Sandbox execution timed out after 2.5s"

    @pytest.mark.timeout(30)
    def test_initialization_with_custom_message(self) -> None:
        """A caller-provided timeout message should be preserved verbatim."""
        err = SandboxTimeoutError(1.0, message="custom timeout")
        assert err.timeout_seconds == 1.0
        assert str(err) == "custom timeout"


class TestSecurityViolationError:
    """Test suite for pysymex._internal.sandbox.errors.SecurityViolationError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = SecurityViolationError("network access")
        assert isinstance(err, SandboxSecurityError)
        assert err.operation == "network access"
        assert err.details is None
        assert str(err) == "Security violation: attempted network access"

    @pytest.mark.timeout(30)
    def test_initialization_with_details(self) -> None:
        """Security errors should include contextual details for auditability."""
        err = SecurityViolationError("file write", details="outside jail")
        assert err.operation == "file write"
        assert err.details == "outside jail"
        assert str(err) == "Security violation: attempted file write (outside jail)"


class TestResourceExhaustedError:
    """Test suite for pysymex._internal.sandbox.errors.ResourceExhaustedError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = ResourceExhaustedError("memory", 256, "MB")
        assert isinstance(err, SandboxResourceError)
        assert err.resource == "memory"
        assert err.limit == 256
        assert err.unit == "MB"
        assert str(err) == "Resource exhausted: memory exceeded limit of 256MB"


class TestSandboxCleanupError:
    """Test suite for pysymex._internal.sandbox.errors.SandboxCleanupError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = SandboxCleanupError("cleanup failed")
        assert isinstance(err, SandboxError)
        assert str(err) == "cleanup failed"


class TestExecutionSandboxErrors:
    """Test execution sandbox errors owned by pysymex._internal.sandbox.errors."""

    @pytest.mark.timeout(30)
    def test_resource_limit_error_keeps_execution_security_base(self) -> None:
        err = ResourceLimitError("limit exceeded")
        assert isinstance(err, SecurityError)
        assert str(err) == "limit exceeded"
