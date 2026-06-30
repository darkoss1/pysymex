# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.config.sandbox.bridge import make_sandbox_config as _make_sandbox_config
from pysymex._internal.logging.root import get_logger
from pysymex._internal.sandbox.bridge.errors import sandbox_result_error
from pysymex._internal.sandbox.bridge.payload import (
    PayloadParseStatus,
    extract_payload,
    validate_worker_envelope,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.config.sandbox.types import SandboxConfig
    from pysymex._internal.sandbox.types import SandboxResult

logger = get_logger(__name__)


def run_json_worker(
    worker_script: str,
    *,
    sandbox_config: Mapping[str, object] | None = None,
    extra_files: Mapping[str, bytes] | None = None,
    input_data: bytes | None = None,
    result_marker: str,
    fail_on_not_ok: bool = True,
) -> tuple[dict[str, object], str, str]:
    """Execute a worker script and parse its marker-delimited JSON envelope.

    Args:
        worker_script: Python source executed as the staged sandbox worker.
        sandbox_config: Optional bridge configuration overrides converted into
            a `SandboxConfig`.
        extra_files: Optional files staged alongside the worker.
        input_data: Optional standard-input bytes supplied to worker execution.
        result_marker: Standard-output line prefix used to locate its JSON
            result envelope.
        fail_on_not_ok: Whether an envelope with `ok=False` becomes
            `SandboxExecutionError`.

    Returns:
        The validated envelope mapping, standard output with result marker
        lines removed, and decoded standard error.

    Raises:
        SandboxProtocolError: If a successful sandbox run has no single valid
            envelope or the envelope has invalid fields.
        SandboxExecutionError: If `fail_on_not_ok` is enabled and the valid
            envelope reports failure.
        SandboxError: If sandbox execution fails; the concrete subclass is
            selected by `sandbox_result_error`.

    Side Effects:
        Opens a `SecureSandbox` context and executes `worker_script` through
        `execute_code`.

    """
    from pysymex._internal.sandbox.runner import SecureSandbox

    all_files: dict[str, bytes] = {}
    if extra_files:
        all_files.update(dict(extra_files))

    from pysymex._internal.sandbox.errors import (
        SandboxExecutionError,
        SandboxProtocolError,
    )

    def _execute_with_config(cfg: SandboxConfig) -> SandboxResult:
        """Execute the staged JSON worker inside one sandbox context."""
        with SecureSandbox(cfg) as sandbox:
            return sandbox.execute_code(
                worker_script,
                filename="_pysymex_sandbox_worker.py",
                input_data=input_data,
                extra_files=all_files,
            )

    config = _make_sandbox_config(sandbox_config)
    sandbox_result = _execute_with_config(config)
    stdout_text = sandbox_result.get_stdout_text()
    stderr_text = sandbox_result.get_stderr_text()
    cleaned_stdout, parsed, parse_status = extract_payload(stdout_text, result_marker)
    if parsed is None:
        message = sandbox_result.error_message or "Sandbox worker produced no result payload"
        if parsed is None:
            if sandbox_result.succeeded:
                if parse_status == PayloadParseStatus.MULTIPLE:
                    msg = "Sandbox worker produced multiple result payloads"
                    raise SandboxProtocolError(msg)
                if parse_status == PayloadParseStatus.MALFORMED:
                    msg = "Sandbox worker produced malformed result payload"
                    raise SandboxProtocolError(msg)
                raise SandboxProtocolError(f"{message}\n{stderr_text}".strip())
            raise sandbox_result_error(
                sandbox_result,
                config,
                f"{message}\n{stderr_text}".strip(),
            )
    validate_worker_envelope(parsed)

    if fail_on_not_ok and not bool(parsed.get("ok", False)):
        error = str(parsed.get("error", "Sandbox worker failed"))
        tb = str(parsed.get("traceback", "")).strip()
        detail = f"{error}\n{tb}".strip()
        raise SandboxExecutionError(detail)

    return parsed, cleaned_stdout, stderr_text


def run_raw_worker(
    worker_script: str,
    *,
    sandbox_config: Mapping[str, object] | None = None,
    extra_files: Mapping[str, bytes] | None = None,
    input_data: bytes | None = None,
) -> bytes:
    """Execute a worker script and return its raw standard-output bytes.

    Args:
        worker_script: Python source executed as the staged sandbox worker.
        sandbox_config: Optional bridge configuration overrides converted into
            a `SandboxConfig`.
        extra_files: Optional files staged alongside the worker.
        input_data: Optional standard-input bytes supplied to worker execution.

    Returns:
        Raw worker standard output from a successful sandbox result.

    Raises:
        SandboxError: If sandbox execution fails; the concrete subclass is
            selected by `sandbox_result_error`.

    Side Effects:
        Opens a `SecureSandbox` context and executes `worker_script` through
        `execute_code`.

    """
    from pysymex._internal.sandbox.runner import SecureSandbox

    all_files: dict[str, bytes] = {}
    if extra_files:
        all_files.update(dict(extra_files))

    def _execute_with_config(cfg: SandboxConfig):
        """Execute the staged raw worker inside one sandbox context."""
        with SecureSandbox(cfg) as sandbox:
            return sandbox.execute_code(
                worker_script,
                filename="_pysymex_sandbox_worker.py",
                input_data=input_data,
                extra_files=all_files,
            )

    config = _make_sandbox_config(sandbox_config)
    result = _execute_with_config(config)
    if not result.succeeded:
        raise sandbox_result_error(result, config, "Sandbox worker failed")
    return result.stdout
