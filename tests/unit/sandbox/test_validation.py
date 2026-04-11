from pathlib import Path

import pytest

from pysymex._constants import MAX_FILE_SIZE
from pysymex.sandbox.execution import ResourceLimitError, SecurityError
from pysymex.sandbox.validation import (
    PathTraversalError,
    SecurityConfig,
    sanitize_function_name,
    validate_bounds,
    validate_config,
    validate_path,
)

class TestPathTraversalError:
    """Test suite for pysymex.sandbox.validation.PathTraversalError."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        err = PathTraversalError("blocked traversal")
        assert isinstance(err, SecurityError)
        assert str(err) == "blocked traversal"


class TestSecurityConfig:
    """Test suite for pysymex.sandbox.validation.SecurityConfig."""

    @pytest.mark.timeout(30)
    def test_initialization(self) -> None:
        """Test basic initialization."""
        cfg = SecurityConfig()
        assert cfg.allow_absolute_paths is True
        assert cfg.allow_symlinks is False
        assert cfg.allowed_directories is None
        assert cfg.max_memory_mb == 512
        assert cfg.max_cpu_seconds == 60
        assert cfg.sandbox_builtins is True
        assert cfg.allow_file_io is False
        assert cfg.allow_network is False

    @pytest.mark.timeout(30)
    def test_initialization_with_custom_limits(self) -> None:
        """Custom security config should preserve explicitly provided policy knobs."""
        cfg = SecurityConfig(max_memory_mb=128, max_cpu_seconds=5, allow_file_io=True)
        assert cfg.max_memory_mb == 128
        assert cfg.max_cpu_seconds == 5
        assert cfg.allow_file_io is True


class TestValidatePath:
    """Test suite for pysymex.sandbox.validation.validate_path."""

    @pytest.mark.timeout(30)
    def test_validate_path_permitted_file_succeeds(self, tmp_path: Path) -> None:
        """Allowed file access should resolve safely within the base directory."""
        file_path = tmp_path / "safe.py"
        file_path.write_text("print('ok')", encoding="utf-8")
        resolved = validate_path(
            file_path,
            must_exist=True,
            must_be_file=True,
            allowed_extensions=[".py"],
            base_directory=tmp_path,
        )
        assert resolved == file_path.resolve()

    @pytest.mark.timeout(30)
    def test_validate_path_forbidden_pattern_fails(self) -> None:
        """Traversal patterns must be blocked to prevent escaping the sandbox root."""
        with pytest.raises(PathTraversalError):
            validate_path("../secret.py", must_exist=False)

    @pytest.mark.timeout(30)
    def test_validate_path_base_directory_escape_fails(self, tmp_path: Path) -> None:
        """Paths outside the declared base directory must be rejected."""
        outside = tmp_path.parent / "outside.py"
        outside.write_text("print('x')", encoding="utf-8")
        with pytest.raises(PathTraversalError):
            validate_path(outside, base_directory=tmp_path)

    @pytest.mark.timeout(30)
    def test_validate_path_extension_restriction_fails(self, tmp_path: Path) -> None:
        """Disallowed extensions should fail validation to reduce execution surface."""
        file_path = tmp_path / "input.txt"
        file_path.write_text("data", encoding="utf-8")
        with pytest.raises(SecurityError):
            validate_path(file_path, allowed_extensions=[".py"])

    @pytest.mark.timeout(30)
    def test_validate_path_directory_rejected_when_file_required(self, tmp_path: Path) -> None:
        """Directory paths must not be accepted when a regular file is required."""
        with pytest.raises(SecurityError):
            validate_path(tmp_path, must_exist=True, must_be_file=True)

    @pytest.mark.timeout(30)
    def test_validate_path_large_file_fails_resource_limit(
        self,
        tmp_path: Path,
    ) -> None:
        """Oversized files must be rejected to prevent memory abuse via input payloads."""
        file_path = tmp_path / "payload.py"
        file_path.write_bytes(b"x" * (MAX_FILE_SIZE + 1))
        with pytest.raises(ResourceLimitError):
            validate_path(file_path)

    @pytest.mark.timeout(30)
    def test_validate_path_nonexistent_allowed_when_not_required(self, tmp_path: Path) -> None:
        """Non-existent paths can be accepted when existence checks are explicitly disabled."""
        missing = tmp_path / "missing.py"
        resolved = validate_path(missing, must_exist=False)
        assert resolved == missing.resolve()


class TestValidateBounds:
    """Test suite for pysymex.sandbox.validation.validate_bounds."""

    @pytest.mark.timeout(30)
    def test_validate_bounds_permitted_value_succeeds(self) -> None:
        """Valid bounds should pass through unchanged."""
        assert validate_bounds(5, "depth", 1, 10) == 5

    @pytest.mark.timeout(30)
    def test_validate_bounds_below_min_fails(self) -> None:
        """Values below configured minimum must be rejected."""
        with pytest.raises(ValueError):
            validate_bounds(0, "depth", 1, 10)

    @pytest.mark.timeout(30)
    def test_validate_bounds_above_max_fails(self) -> None:
        """Values above configured maximum must be rejected."""
        with pytest.raises(ValueError):
            validate_bounds(11, "depth", 1, 10)


class TestValidateConfig:
    """Test suite for pysymex.sandbox.validation.validate_config."""

    @pytest.mark.timeout(30)
    def test_validate_config_permitted_values_succeed(self) -> None:
        """A valid execution config should return normalized values."""
        cfg = validate_config(max_paths=10, max_depth=5, max_iterations=20, timeout=2.0)
        assert cfg["max_paths"] == 10
        assert cfg["max_depth"] == 5
        assert cfg["max_iterations"] == 20
        assert cfg["timeout"] == 2.0

    @pytest.mark.timeout(30)
    def test_validate_config_invalid_bounds_fail(self) -> None:
        """Invalid path-depth constraints must fail fast."""
        with pytest.raises(ValueError):
            validate_config(max_paths=0)

    @pytest.mark.timeout(30)
    def test_validate_config_timeout_is_clamped(self) -> None:
        """Timeout must be clamped into safe operational bounds."""
        low = validate_config(timeout=0.0)
        high = validate_config(timeout=999999.0)
        assert low["timeout"] == 0.1
        assert isinstance(high["timeout"], float)
        assert high["timeout"] >= 0.1


class TestSanitizeFunctionName:
    """Test suite for pysymex.sandbox.validation.sanitize_function_name."""

    @pytest.mark.timeout(30)
    def test_sanitize_function_name_valid_name_succeeds(self) -> None:
        """Valid function identifiers should pass unchanged."""
        assert sanitize_function_name("safe_name_1") == "safe_name_1"

    @pytest.mark.timeout(30)
    def test_sanitize_function_name_empty_fails(self) -> None:
        """Empty names must be rejected to prevent ambiguous symbol resolution."""
        with pytest.raises(ValueError):
            sanitize_function_name("")

    @pytest.mark.timeout(30)
    def test_sanitize_function_name_illegal_chars_fail(self) -> None:
        """Non-identifier characters must be blocked in user-supplied function names."""
        with pytest.raises(ValueError):
            sanitize_function_name("bad-name")

    @pytest.mark.timeout(30)
    def test_sanitize_function_name_digit_prefix_fails(self) -> None:
        """Names starting with digits must be rejected for Python identifier safety."""
        with pytest.raises(ValueError):
            sanitize_function_name("1start")

    @pytest.mark.timeout(30)
    def test_sanitize_function_name_keyword_fails(self) -> None:
        """Python keywords must be blocked to prevent parse-time ambiguity."""
        with pytest.raises(ValueError):
            sanitize_function_name("class")
