import ast
import json
import re
from unittest.mock import patch

import pytest

from pysymex._internal.config.sandbox.types import SandboxConfig
from pysymex._internal.sandbox.bridge.bytecode import (
    bytecode_extraction_session,
    extract_bytecode_batch,
    extract_bytecode,
)
from pysymex._internal.sandbox.errors import (
    SandboxExecutionError,
    SandboxProtocolError,
    SandboxResourceError,
    SandboxSetupError,
)
from pysymex._internal.sandbox.types import ExecutionStatus, SandboxResult
from tests.unit.sandbox.bridge_test_helpers import create_bridge_payload, is_object_mapping


@pytest.mark.timeout(30)
def test_extract_bytecode() -> None:
    """Test extract_bytecode behavior."""
    code_obj = compile("value = 5\n", "demo.py", "exec")

    def mock_run_raw_worker(worker_script: str, **kwargs: object) -> bytes:
        match = re.search(r"sys\.stdout\.buffer\.write\((b'.*?') \+ _payload\)", worker_script)
        assert match is not None
        sandbox_cfg = kwargs.get("sandbox_config")
        assert is_object_mapping(sandbox_cfg)
        assert "harness_install_audit_hook" not in sandbox_cfg
        assert "harness_allowed_imports" not in sandbox_cfg
        assert "harness_blocked_modules" not in sandbox_cfg
        marker_obj: object = ast.literal_eval(match.group(1))
        assert isinstance(marker_obj, bytes)
        marker = marker_obj
        payload = create_bridge_payload(code_obj, "demo.py")
        return marker + payload

    with patch(
        "pysymex._internal.sandbox.bridge.bytecode._run_raw_worker", side_effect=mock_run_raw_worker
    ):
        blob = extract_bytecode(b"value = 5\n", "demo.py")
    rebuilt = blob.reconstruct()
    assert rebuilt.co_filename == "demo.py"


@pytest.mark.timeout(30)
def test_extract_bytecode_failure_does_not_downgrade() -> None:
    """Scanner bytecode extraction fails closed instead of changing sandbox boundary."""
    configs: list[SandboxConfig] = []

    class FakeSandbox:
        def __init__(self, config: SandboxConfig) -> None:
            configs.append(config)
            self.config = config

        def __enter__(self) -> "FakeSandbox":
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            _exc_val: BaseException | None,
            _exc_tb: object,
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
            return SandboxResult(
                status=ExecutionStatus.FAILED,
                exit_code=1,
                stderr=(
                    b"unshare: failed to execute /opt/venv/bin/python: No such file or directory\n"
                ),
            )

    with patch("pysymex._internal.sandbox.runner.SecureSandbox", FakeSandbox):
        with pytest.raises(SandboxExecutionError, match="unshare: failed to execute"):
            extract_bytecode(
                b"value = 5\n",
                "demo.py",
            )

    assert len(configs) == 1


@pytest.mark.timeout(30)
def test_extract_bytecode_setup_failure_stays_visible() -> None:
    """Setup failures must not silently downgrade the sandbox boundary."""

    class FakeSandbox:
        def __init__(self, config: SandboxConfig) -> None:
            self.config = config

        def __enter__(self) -> "FakeSandbox":
            raise SandboxSetupError("strong backend unavailable")

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            _exc_val: BaseException | None,
            _exc_tb: object,
        ) -> None:
            return None

    with patch("pysymex._internal.sandbox.runner.SecureSandbox", FakeSandbox):
        with pytest.raises(SandboxSetupError, match="strong backend unavailable"):
            extract_bytecode(
                b"value = 5\n",
                "demo.py",
            )


@pytest.mark.timeout(30)
def test_extract_bytecode_rejects_missing_worker_marker_as_protocol_error() -> None:
    with patch(
        "pysymex._internal.sandbox.bridge.bytecode._run_raw_worker",
        return_value=b"not-the-marker{}",
    ):
        with pytest.raises(SandboxProtocolError, match="no marker"):
            extract_bytecode(b"value = 5\n", "demo.py")


@pytest.mark.timeout(30)
def test_extract_bytecode_rejects_oversized_worker_payload_as_resource_error() -> None:
    def mock_run_raw_worker(worker_script: str, **kwargs: object) -> bytes:
        _ = kwargs
        match = re.search(r"sys\.stdout\.buffer\.write\((b'.*?') \+ _payload\)", worker_script)
        assert match is not None
        marker_obj: object = ast.literal_eval(match.group(1))
        assert isinstance(marker_obj, bytes)
        return marker_obj + (b"x" * 5)

    with patch(
        "pysymex._internal.sandbox.bridge.bytecode._run_raw_worker", side_effect=mock_run_raw_worker
    ):
        with pytest.raises(SandboxResourceError, match="exceeds configured result size"):
            extract_bytecode(
                b"value = 5\n",
                "demo.py",
                sandbox_config={"max_result_bytes": 4},
            )


@pytest.mark.timeout(30)
def test_bytecode_extraction_session_reuses_verified_sandbox() -> None:
    code_obj = compile("value = 5\n", "demo.py", "exec")
    payload = create_bridge_payload(code_obj, "demo.py")
    execute_calls = 0
    reset_calls = 0

    class FakeSandbox:
        def __init__(self, config: SandboxConfig) -> None:
            self.config = config

        def __enter__(self) -> "FakeSandbox":
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            _exc_val: BaseException | None,
            _exc_tb: object,
        ) -> None:
            return None

        def reset_workspace(self) -> None:
            nonlocal reset_calls
            reset_calls += 1

        def execute_code(
            self,
            code: str | bytes,
            *,
            filename: str = "sandbox_code.py",
            input_data: bytes | None = None,
            extra_files: dict[str, bytes] | None = None,
        ) -> SandboxResult:
            nonlocal execute_calls
            _ = filename
            _ = input_data
            _ = extra_files
            execute_calls += 1
            assert isinstance(code, str)
            match = re.search(r"sys\.stdout\.buffer\.write\((b'.*?') \+ _payload\)", code)
            assert match is not None
            marker_obj: object = ast.literal_eval(match.group(1))
            assert isinstance(marker_obj, bytes)
            return SandboxResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout=marker_obj + payload,
            )

    with (
        patch("pysymex._internal.sandbox.runner.SecureSandbox", FakeSandbox),
        patch("pysymex._internal.sandbox.bridge.bytecode._run_raw_worker") as run_raw_worker,
        bytecode_extraction_session(),
    ):
        first = extract_bytecode(
            b"value = 5\n",
            "demo.py",
        )
        second = extract_bytecode(
            b"value = 6\n",
            "demo.py",
        )

    assert first.reconstruct().co_filename == "demo.py"
    assert second.reconstruct().co_filename == "demo.py"
    assert execute_calls == 2
    assert reset_calls == 4
    run_raw_worker.assert_not_called()


@pytest.mark.timeout(30)
def test_extract_bytecode_batch_uses_one_worker_for_multiple_sources() -> None:
    code_a = compile("value = 1\n", "a.py", "exec")
    code_b = compile("value = 2\n", "b.py", "exec")
    worker_calls = 0

    def mock_run_raw_worker(worker_script: str, **kwargs: object) -> bytes:
        nonlocal worker_calls
        worker_calls += 1
        match = re.search(r"sys\.stdout\.buffer\.write\((b'.*?') \+ _payload\)", worker_script)
        assert match is not None
        input_data = kwargs.get("input_data")
        assert isinstance(input_data, bytes)
        request = json.loads(input_data.decode("utf-8"))
        assert [item["filename"] for item in request["files"]] == ["a.py", "b.py"]
        marker_obj: object = ast.literal_eval(match.group(1))
        assert isinstance(marker_obj, bytes)
        payload = {
            "files": [
                {
                    "filename": "a.py",
                    "payload": json.loads(create_bridge_payload(code_a, "a.py").decode("utf-8")),
                },
                {
                    "filename": "b.py",
                    "payload": json.loads(create_bridge_payload(code_b, "b.py").decode("utf-8")),
                },
            ],
        }
        return marker_obj + json.dumps(payload, ensure_ascii=True).encode("utf-8")

    with patch(
        "pysymex._internal.sandbox.bridge.bytecode._run_raw_worker",
        side_effect=mock_run_raw_worker,
    ):
        blobs = extract_bytecode_batch(
            {
                "a.py": b"value = 1\n",
                "b.py": b"value = 2\n",
            },
        )

    assert worker_calls == 1
    assert sorted(blobs) == ["a.py", "b.py"]
    assert blobs["a.py"].reconstruct().co_filename == "a.py"
    assert blobs["b.py"].reconstruct().co_filename == "b.py"
