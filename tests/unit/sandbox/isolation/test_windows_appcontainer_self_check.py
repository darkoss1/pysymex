from __future__ import annotations

from typing import Final

import pytest

from pysymex._internal.config.sandbox.types import SandboxConfig
from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.appcontainer.selfcheck.code import (
    build_combined_self_check_code,
)
from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import NativeProcessResult
from pysymex._internal.sandbox.types import ExecutionStatus
from tests.unit.sandbox.isolation.windows_appcontainer_helpers import (
    InspectableWindowsAppContainerBackend,
)

_EXPECTED_SELF_CHECK_PROBES: Final[tuple[str, ...]] = (
    "launch-boundary",
    "runtime-write-deny",
    "runtime-delete-deny",
    "runtime-rename-deny",
    "environment-deny",
    "filesystem-deny",
    "lpac-deny",
    "native-extension-deny",
    "registry-deny",
    "subprocess-deny",
    "network-deny",
)


def _self_check_code() -> str:
    return build_combined_self_check_code(
        expected_profile=r"C:\Users\pysymex-appcontainer",
        expected_pythonhome=r"C:\pysymex-runtime",
        denied_file=r"C:\host\denied.txt",
        lpac_probe_file=r"C:\host\lpac.txt",
        registry_probe_key=r"Software\pysymex_probe",
        registry_probe_value="secret",
        registry_probe_secret="registry-secret",
        network_host="127.0.0.1",
        network_port=49152,
    )


def _native_result(
    stdout: bytes,
    *,
    status: ExecutionStatus = ExecutionStatus.SUCCESS,
    exit_code: int | None = 0,
) -> NativeProcessResult:
    return NativeProcessResult(
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=b"",
        wall_time_ms=1.0,
    )


@pytest.mark.timeout(30)
def test_combined_self_check_code_compiles_and_keeps_required_probe_labels() -> None:
    code = _self_check_code()

    _ = compile(code, "<pysymex-appcontainer-self-check>", "exec")

    for probe in _EXPECTED_SELF_CHECK_PROBES:
        assert repr(probe) in code


@pytest.mark.timeout(30)
def test_combined_self_check_validation_accepts_complete_child_report() -> None:
    backend = InspectableWindowsAppContainerBackend(SandboxConfig())
    stdout = b'{"checks":["launch-boundary"],"failures":[],"missing":[]}'

    backend.validate_combined_self_check_for_test(_native_result(stdout))


@pytest.mark.timeout(30)
def test_combined_self_check_validation_rejects_child_reported_denial_escape() -> None:
    backend = InspectableWindowsAppContainerBackend(SandboxConfig())
    stdout = b'{"checks":[],"failures":["network-deny"],"missing":["filesystem-deny"]}'

    with pytest.raises(SandboxSetupError, match="network-deny"):
        backend.validate_combined_self_check_for_test(_native_result(stdout))
