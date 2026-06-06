import json
import re

import pytest
from unittest.mock import patch

from pysymex.sandbox.errors import (
    SandboxExecutionError,
    SandboxProtocolError,
    SandboxResourceError,
    SandboxSetupError,
    SandboxSecurityError,
    SandboxTimeoutError,
)
from pysymex.config.sandbox_bridge import make_sandbox_config
from pysymex.sandbox.bridge.bytecode import extract_bytecode
from pysymex.sandbox.bridge.module import extract_module
from pysymex.sandbox.types import ExecutionStatus, SandboxConfig, SandboxResult
from tests.unit.sandbox.bridge_test_helpers import extract_json_worker_marker


@pytest.mark.timeout(30)
def test_make_sandbox_config_rejects_unknown_backend_with_domain_error() -> None:
    with pytest.raises(SandboxSetupError, match="Unknown sandbox backend"):
        make_sandbox_config({"backend": "LEGACY_BACKEND"})


@pytest.mark.timeout(30)
def test_make_sandbox_config_uses_secure_defaults() -> None:
    """Bridge config normalization preserves SandboxConfig secure defaults."""
    config = make_sandbox_config({})
    assert config.limits.timeout_seconds > 0
    assert config._block_network is True  # pyright: ignore[reportPrivateUsage]


@pytest.mark.timeout(30)
def test_extract_module_rejects_malformed_success_output_as_protocol_error() -> None:
    class FakeSandbox:
        def __init__(self, config: SandboxConfig) -> None:
            self.config = config

        def __enter__(self) -> "FakeSandbox":
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: object,
        ) -> None:
            return None

        def execute_code(
            self,
            code: str | bytes,
            *,
            filename: str = "sandbox_code.py",
            input_data: bytes | None = None,
            extra_files: dict[str, bytes] | None = None,
        ) -> SandboxResult:
            _ = code
            _ = filename
            _ = input_data
            _ = extra_files
            return SandboxResult(status=ExecutionStatus.SUCCESS, exit_code=0, stdout=b"noise\n")

    with patch("pysymex.sandbox.SecureSandbox", FakeSandbox):
        with pytest.raises(SandboxProtocolError, match="produced no result payload"):
            extract_module(
                b"def target():\n    return 1\n",
                "target.py",
                sandbox_config={"backend": "WINDOWS_APPCONTAINER"},
            )


@pytest.mark.timeout(30)
def test_extract_module_reports_worker_payload_failure_as_execution_error() -> None:
    class FakeSandbox:
        def __init__(self, config: SandboxConfig) -> None:
            self.config = config

        def __enter__(self) -> "FakeSandbox":
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: object,
        ) -> None:
            return None

        def execute_code(
            self,
            code: str | bytes,
            *,
            filename: str = "sandbox_code.py",
            input_data: bytes | None = None,
            extra_files: dict[str, bytes] | None = None,
        ) -> SandboxResult:
            _ = filename
            _ = input_data
            _ = extra_files
            assert isinstance(code, str)
            marker_match = re.search(r"_MARKER = '([^']+)'", code)
            assert marker_match is not None
            marker = marker_match.group(1)
            payload = json.dumps({"ok": False, "error": "ValueError: bad"})
            return SandboxResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout=(marker + payload).encode("utf-8"),
            )

    with patch("pysymex.sandbox.SecureSandbox", FakeSandbox):
        with pytest.raises(SandboxExecutionError, match="ValueError: bad"):
            extract_module(
                b"def target():\n    return 1\n",
                "target.py",
                sandbox_config={"backend": "WINDOWS_APPCONTAINER"},
            )


@pytest.mark.timeout(30)
@pytest.mark.parametrize(
    ("status", "expected_error"),
    [
        (ExecutionStatus.TIMEOUT, SandboxTimeoutError),
        (ExecutionStatus.MEMORY_EXCEEDED, SandboxResourceError),
        (ExecutionStatus.SECURITY_VIOLATION, SandboxSecurityError),
    ],
)
def test_run_raw_worker_maps_sandbox_status_to_domain_error(
    status: ExecutionStatus,
    expected_error: type[BaseException],
) -> None:
    class FakeSandbox:
        def __init__(self, config: SandboxConfig) -> None:
            self.config = config

        def __enter__(self) -> "FakeSandbox":
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: object,
        ) -> None:
            return None

        def execute_code(
            self,
            code: str | bytes,
            *,
            filename: str = "sandbox_code.py",
            input_data: bytes | None = None,
            extra_files: dict[str, bytes] | None = None,
        ) -> SandboxResult:
            _ = code
            _ = filename
            _ = input_data
            _ = extra_files
            return SandboxResult(status=status, error_message=f"{status.name} failure")

    with patch("pysymex.sandbox.SecureSandbox", FakeSandbox):
        with pytest.raises(expected_error, match=f"{status.name} failure"):
            extract_bytecode(
                b"value = 5\n",
                "demo.py",
                sandbox_config={"backend": "WINDOWS_APPCONTAINER"},
            )


@pytest.mark.timeout(30)
def test_json_worker_rejects_duplicate_result_markers_as_protocol_error() -> None:
    class FakeSandbox:
        def __init__(self, config: SandboxConfig) -> None:
            self.config = config

        def __enter__(self) -> "FakeSandbox":
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: object,
        ) -> None:
            return None

        def execute_code(
            self,
            code: str | bytes,
            *,
            filename: str = "sandbox_code.py",
            input_data: bytes | None = None,
            extra_files: dict[str, bytes] | None = None,
        ) -> SandboxResult:
            _ = filename
            _ = input_data
            _ = extra_files
            assert isinstance(code, str)
            marker = extract_json_worker_marker(code)
            payload = json.dumps({"ok": True, "payload": {}})
            stdout = f"{marker}{payload}\n{marker}{payload}\n".encode("utf-8")
            return SandboxResult(status=ExecutionStatus.SUCCESS, exit_code=0, stdout=stdout)

    with patch("pysymex.sandbox.SecureSandbox", FakeSandbox):
        with pytest.raises(SandboxProtocolError, match="multiple result payloads"):
            extract_module(
                b"def target():\n    return 1\n",
                "target.py",
                sandbox_config={"backend": "WINDOWS_APPCONTAINER"},
            )


@pytest.mark.timeout(30)
def test_json_worker_rejects_unexpected_envelope_fields_as_protocol_error() -> None:
    class FakeSandbox:
        def __init__(self, config: SandboxConfig) -> None:
            self.config = config

        def __enter__(self) -> "FakeSandbox":
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: object,
        ) -> None:
            return None

        def execute_code(
            self,
            code: str | bytes,
            *,
            filename: str = "sandbox_code.py",
            input_data: bytes | None = None,
            extra_files: dict[str, bytes] | None = None,
        ) -> SandboxResult:
            _ = filename
            _ = input_data
            _ = extra_files
            assert isinstance(code, str)
            marker = extract_json_worker_marker(code)
            payload = json.dumps({"ok": True, "payload": {}, "surprise": True})
            return SandboxResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout=(marker + payload).encode("utf-8"),
            )

    with patch("pysymex.sandbox.SecureSandbox", FakeSandbox):
        with pytest.raises(SandboxProtocolError, match="unexpected envelope"):
            extract_module(
                b"def target():\n    return 1\n",
                "target.py",
                sandbox_config={"backend": "WINDOWS_APPCONTAINER"},
            )


@pytest.mark.timeout(30)
def test_json_worker_rejects_non_boolean_ok_as_protocol_error() -> None:
    class FakeSandbox:
        def __init__(self, config: SandboxConfig) -> None:
            self.config = config

        def __enter__(self) -> "FakeSandbox":
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: object,
        ) -> None:
            return None

        def execute_code(
            self,
            code: str | bytes,
            *,
            filename: str = "sandbox_code.py",
            input_data: bytes | None = None,
            extra_files: dict[str, bytes] | None = None,
        ) -> SandboxResult:
            _ = filename
            _ = input_data
            _ = extra_files
            assert isinstance(code, str)
            marker = extract_json_worker_marker(code)
            payload = json.dumps({"ok": "true", "payload": {}})
            return SandboxResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout=(marker + payload).encode("utf-8"),
            )

    with patch("pysymex.sandbox.SecureSandbox", FakeSandbox):
        with pytest.raises(SandboxProtocolError, match="'ok' must be boolean"):
            extract_module(
                b"def target():\n    return 1\n",
                "target.py",
                sandbox_config={"backend": "WINDOWS_APPCONTAINER"},
            )
