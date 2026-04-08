# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Strict sandbox bridge with minimal data-boundary workers.

The host process keeps all PySyMex orchestration and analysis logic.
Only untrusted target code operations cross into the sandbox as raw
bytes/JSON requests.
"""

from __future__ import annotations

import json
import marshal
import sys
import textwrap
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import CodeType
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex.sandbox import SandboxConfig

_BYTECODE_MARKER = b"__PYSYMEX_BYTECODE__"
_CONCRETE_MARKER = "__PYSYMEX_CONCRETE__"
_MAX_BYTECODE_PAYLOAD_BYTES = 10 * 1024 * 1024


@dataclass(slots=True)
class ConcreteResult:
    succeeded: bool
    return_value: object | None = None
    exception_type: str | None = None
    exception_message: str | None = None
    traceback: str | None = None
    stdout: str = ""
    stderr: str = ""


@dataclass(slots=True, frozen=True)
class BytecodeBlob:
    payload: bytes
    filename: str
    producer_python: tuple[int, int] | None = None

    def reconstruct(self) -> CodeType:
        if not self.payload:
            raise ValueError("Sandbox bytecode payload is empty")
        if len(self.payload) > _MAX_BYTECODE_PAYLOAD_BYTES:
            raise ValueError("Sandbox bytecode payload exceeds size limit")

        if self.producer_python is not None:
            current = (sys.version_info.major, sys.version_info.minor)
            if self.producer_python != current:
                raise ValueError("Sandbox bytecode producer Python version does not match host")

        try:
            code_obj = marshal.loads(self.payload)
        except (TypeError, ValueError, EOFError) as exc:
            raise ValueError("Invalid sandbox bytecode payload") from exc

        if not isinstance(code_obj, CodeType):
            raise ValueError("Sandbox bytecode payload did not decode to CodeType")
        if code_obj.co_filename != self.filename:
            raise ValueError("Sandbox bytecode payload filename metadata mismatch")
        return code_obj


def _to_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _to_float(value: object, default: float) -> float:
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def _to_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def _make_sandbox_config(
    overrides: Mapping[str, object] | None = None,
) -> SandboxConfig:
    from pysymex._constants import SANDBOX_IMPORT_ALLOWLIST
    from pysymex.sandbox import SandboxBackend, SandboxConfig
    from pysymex.sandbox._types import ResourceLimits, SecurityCapabilities

    raw = dict(overrides or {})
    aliases = {
        "timeout": "timeout_seconds",
        "max_memory_mb": "memory_mb",
        "max_cpu_seconds": "cpu_seconds",
        "max_output_bytes": "max_output_bytes",
    }

    _KNOWN_KEYS = {
        "timeout_seconds",
        "cpu_seconds",
        "memory_mb",
        "max_processes",
        "max_file_descriptors",
        "max_file_size_mb",
        "max_output_bytes",
        "backend",
        "working_directory",
        "environment",
        "python_executable",
        "capture_output",
        "allow_stdin",
        "allow_weak_backends",
        "_block_network",
        "_block_filesystem",
        "_block_process_spawn",
        "harness_blocked_modules",
        "harness_allowed_imports",
        "harness_restrict_builtins",
        "harness_install_audit_hook",
        "harness_block_ast_imports",
        "required_capabilities",
        "allow_compat_fallback",
    }

    normalized: dict[str, object] = {}
    for key, value in raw.items():
        norm_key = aliases.get(key, key)
        if norm_key not in _KNOWN_KEYS:
            import warnings

            warnings.warn(f"Unknown sandbox config key: {key}")
        normalized[norm_key] = value

    default_limits = ResourceLimits()
    limits = ResourceLimits(
        timeout_seconds=_to_float(
            normalized.get("timeout_seconds", default_limits.timeout_seconds),
            default_limits.timeout_seconds,
        ),
        cpu_seconds=_to_int(
            normalized.get("cpu_seconds", default_limits.cpu_seconds),
            default_limits.cpu_seconds,
        ),
        memory_mb=_to_int(
            normalized.get("memory_mb", default_limits.memory_mb),
            default_limits.memory_mb,
        ),
        max_processes=_to_int(
            normalized.get("max_processes", default_limits.max_processes),
            default_limits.max_processes,
        ),
        max_file_descriptors=_to_int(
            normalized.get("max_file_descriptors", default_limits.max_file_descriptors),
            default_limits.max_file_descriptors,
        ),
        max_file_size_mb=_to_int(
            normalized.get("max_file_size_mb", default_limits.max_file_size_mb),
            default_limits.max_file_size_mb,
        ),
        max_output_bytes=_to_int(
            normalized.get("max_output_bytes", default_limits.max_output_bytes),
            default_limits.max_output_bytes,
        ),
    )

    backend_raw = normalized.get("backend")
    backend: SandboxBackend | None = None
    if isinstance(backend_raw, SandboxBackend):
        backend = backend_raw
    elif isinstance(backend_raw, str):
        backend_key = backend_raw.strip().upper()
        backend = SandboxBackend.__members__.get(backend_key)

    working_dir_raw = normalized.get("working_directory", None)
    if isinstance(working_dir_raw, Path):
        working_directory = working_dir_raw
    elif isinstance(working_dir_raw, str):
        working_directory = Path(working_dir_raw)
    else:
        working_directory = None

    env_raw = normalized.get("environment")
    environment: dict[str, str] = {}
    if isinstance(env_raw, Mapping):
        for key, value in env_raw.items():
            environment[str(key)] = str(value)

    python_executable_raw = normalized.get("python_executable")
    python_executable = python_executable_raw if isinstance(python_executable_raw, str) else None

    capture_output = _to_bool(normalized.get("capture_output", True), True)
    allow_stdin = _to_bool(normalized.get("allow_stdin", False), False)
    allow_weak_backends = _to_bool(normalized.get("allow_weak_backends", False), False)
    block_network = _to_bool(normalized.get("_block_network", True), True)
    block_filesystem = _to_bool(normalized.get("_block_filesystem", True), True)
    block_process_spawn = _to_bool(normalized.get("_block_process_spawn", True), True)

    harness_modules_raw = normalized.get("harness_blocked_modules")
    harness_blocked: frozenset[str] | None = None
    if isinstance(harness_modules_raw, frozenset):
        harness_blocked = harness_modules_raw
    elif isinstance(harness_modules_raw, (set, tuple, list)):
        harness_blocked = frozenset(str(m) for m in harness_modules_raw)
    else:
        harness_blocked = None

    allowed_imports_raw = normalized.get("harness_allowed_imports")
    harness_allowed_imports: frozenset[str] | None
    if isinstance(allowed_imports_raw, frozenset):
        harness_allowed_imports = allowed_imports_raw
    elif isinstance(allowed_imports_raw, (set, tuple, list)):
        harness_allowed_imports = frozenset(str(m) for m in allowed_imports_raw)
    elif allowed_imports_raw is None:
        harness_allowed_imports = SANDBOX_IMPORT_ALLOWLIST
    else:
        harness_allowed_imports = SANDBOX_IMPORT_ALLOWLIST

    harness_restrict = _to_bool(
        normalized.get("harness_restrict_builtins", True),
        True,
    )
    harness_install_audit_hook = _to_bool(
        normalized.get("harness_install_audit_hook", True),
        True,
    )
    harness_block_ast_imports = _to_bool(
        normalized.get("harness_block_ast_imports", True),
        True,
    )

    required_caps: SecurityCapabilities | None = None
    required_caps_raw = normalized.get("required_capabilities")
    if isinstance(required_caps_raw, SecurityCapabilities):
        required_caps = required_caps_raw
    elif isinstance(required_caps_raw, Mapping):
        required_caps = SecurityCapabilities(
            process_isolation=_to_bool(required_caps_raw.get("process_isolation", False), False),
            filesystem_jail=_to_bool(required_caps_raw.get("filesystem_jail", False), False),
            network_blocking=_to_bool(required_caps_raw.get("network_blocking", False), False),
            syscall_filtering=_to_bool(required_caps_raw.get("syscall_filtering", False), False),
            memory_limits=_to_bool(required_caps_raw.get("memory_limits", False), False),
            cpu_limits=_to_bool(required_caps_raw.get("cpu_limits", False), False),
            process_limits=_to_bool(required_caps_raw.get("process_limits", False), False),
        )

    return SandboxConfig(
        limits=limits,
        backend=backend,
        working_directory=working_directory,
        environment=environment,
        python_executable=python_executable,
        capture_output=capture_output,
        allow_stdin=allow_stdin,
        allow_weak_backends=allow_weak_backends,
        required_capabilities=required_caps,
        harness_blocked_modules=harness_blocked,
        harness_allowed_imports=harness_allowed_imports,
        harness_restrict_builtins=harness_restrict,
        harness_install_audit_hook=harness_install_audit_hook,
        harness_block_ast_imports=harness_block_ast_imports,
        _block_network=block_network,
        _block_filesystem=block_filesystem,
        _block_process_spawn=block_process_spawn,
    )


def _extract_payload(stdout_text: str, marker: str) -> tuple[str, dict[str, object] | None]:
    output_lines: list[str] = []
    parsed: dict[str, object] | None = None
    for line in stdout_text.splitlines():
        if line.startswith(marker):
            raw_payload = line[len(marker) :]
            try:
                loaded = json.loads(raw_payload)
                parsed = cast("dict[str, object]", loaded) if isinstance(loaded, dict) else None
            except json.JSONDecodeError:
                parsed = None
            continue
        output_lines.append(line)
    cleaned = "\n".join(output_lines)
    if stdout_text.endswith("\n") and cleaned:
        cleaned += "\n"
    return cleaned, parsed


def _run_json_worker(
    worker_script: str,
    *,
    sandbox_config: Mapping[str, object] | None = None,
    extra_files: Mapping[str, bytes] | None = None,
    input_data: bytes | None = None,
    result_marker: str,
    fail_on_not_ok: bool = True,
) -> tuple[dict[str, object], str, str]:
    from pysymex.sandbox import SandboxBackend, SandboxResult, SecureSandbox
    from pysymex.sandbox._types import ExecutionStatus

    all_files: dict[str, bytes] = {}
    if extra_files:
        all_files.update(dict(extra_files))

    def _execute_with_config(cfg: SandboxConfig) -> SandboxResult:
        with SecureSandbox(cfg) as sandbox:
            return sandbox.execute_code(
                worker_script,
                filename="_pysymex_sandbox_worker.py",
                input_data=input_data,
                extra_files=all_files,
            )

    config = _make_sandbox_config(sandbox_config)
    allow_compat_fallback = _to_bool(
        (sandbox_config or {}).get("allow_compat_fallback", True),
        False,
    )
    try:
        sandbox_result = _execute_with_config(config)
    except Exception:
        if not allow_compat_fallback:
            raise
        if sandbox_config is not None and "backend" in sandbox_config:
            raise
        fallback_config = dict(sandbox_config or {})
        fallback_config["backend"] = SandboxBackend.SUBPROCESS
        fallback_config["allow_weak_backends"] = True
        sandbox_result = _execute_with_config(_make_sandbox_config(fallback_config))

    fallback_attempted = False
    launch_error_text = "\n".join(
        (
            sandbox_result.error_message or "",
            sandbox_result.get_stderr_text(),
            sandbox_result.get_stdout_text(),
        )
    )
    launch_error_lower = launch_error_text.lower()
    if (
        allow_compat_fallback
        and sandbox_result.status
        in {ExecutionStatus.CRASH, ExecutionStatus.SETUP_ERROR, ExecutionStatus.FAILED}
        and (
            "Unable to create process using" in launch_error_text
            or "failed to spawn" in launch_error_lower
            or "fork failed" in launch_error_lower
            or "resource temporarily unavailable" in launch_error_lower
            or "unshare:" in launch_error_lower
            or "trampoline" in launch_error_lower
            or "failed to execute" in launch_error_lower
            or "no such file or directory" in launch_error_lower
        )
    ):
        if sandbox_config is not None and "backend" in sandbox_config:
            pass
        else:
            import warnings

            warnings.warn(
                "Sandbox process creation failed. Falling back to weak SUBPROCESS backend due to allow_compat_fallback=True"
            )
            fallback_config = dict(sandbox_config or {})
            fallback_config["backend"] = SandboxBackend.SUBPROCESS
            fallback_config["allow_weak_backends"] = True
            sandbox_result = _execute_with_config(_make_sandbox_config(fallback_config))
            fallback_attempted = True

    stdout_text = sandbox_result.get_stdout_text()
    stderr_text = sandbox_result.get_stderr_text()
    cleaned_stdout, parsed = _extract_payload(stdout_text, result_marker)
    if parsed is None:
        if (
            allow_compat_fallback
            and not fallback_attempted
            and (sandbox_config is None or "backend" not in sandbox_config)
            and sandbox_result.status
            in {ExecutionStatus.CRASH, ExecutionStatus.SETUP_ERROR, ExecutionStatus.FAILED}
        ):
            import warnings

            warnings.warn(
                "Sandbox process creation failed. Falling back to weak SUBPROCESS backend due to allow_compat_fallback=True"
            )
            fallback_config = dict(sandbox_config or {})
            fallback_config["backend"] = SandboxBackend.SUBPROCESS
            fallback_config["allow_weak_backends"] = True
            sandbox_result = _execute_with_config(_make_sandbox_config(fallback_config))
            stdout_text = sandbox_result.get_stdout_text()
            stderr_text = sandbox_result.get_stderr_text()
            cleaned_stdout, parsed = _extract_payload(stdout_text, result_marker)
        message = sandbox_result.error_message or "Sandbox worker produced no result payload"
        if parsed is None:
            raise RuntimeError(f"{message}\n{stderr_text}".strip())

    if fail_on_not_ok and not bool(parsed.get("ok", False)):
        error = str(parsed.get("error", "Sandbox worker failed"))
        tb = str(parsed.get("traceback", "")).strip()
        detail = f"{error}\n{tb}".strip()
        raise RuntimeError(detail)

    return parsed, cleaned_stdout, stderr_text


def _run_raw_worker(
    worker_script: str,
    *,
    sandbox_config: Mapping[str, object] | None = None,
    extra_files: Mapping[str, bytes] | None = None,
    input_data: bytes | None = None,
) -> bytes:
    from pysymex.sandbox import SandboxBackend, SecureSandbox
    from pysymex.sandbox._types import ExecutionStatus

    all_files: dict[str, bytes] = {}
    if extra_files:
        all_files.update(dict(extra_files))

    def _execute_with_config(cfg: SandboxConfig):
        with SecureSandbox(cfg) as sandbox:
            return sandbox.execute_code(
                worker_script,
                filename="_pysymex_sandbox_worker.py",
                input_data=input_data,
                extra_files=all_files,
            )

    config = _make_sandbox_config(sandbox_config)
    allow_compat_fallback = _to_bool(
        (sandbox_config or {}).get("allow_compat_fallback", True),
        False,
    )
    try:
        result = _execute_with_config(config)
    except Exception:
        if not allow_compat_fallback:
            raise
        if sandbox_config is not None and "backend" in sandbox_config:
            raise
        fallback_config = dict(sandbox_config or {})
        fallback_config["backend"] = SandboxBackend.SUBPROCESS
        fallback_config["allow_weak_backends"] = True
        result = _execute_with_config(_make_sandbox_config(fallback_config))

    launch_error_text = "\n".join(
        (
            result.error_message or "",
            result.get_stderr_text(),
            result.get_stdout_text(),
        )
    )
    launch_error_lower = launch_error_text.lower()
    if (
        allow_compat_fallback
        and result.status
        in {ExecutionStatus.CRASH, ExecutionStatus.SETUP_ERROR, ExecutionStatus.FAILED}
        and (
            "Unable to create process using" in launch_error_text
            or "failed to spawn" in launch_error_lower
            or "fork failed" in launch_error_lower
            or "resource temporarily unavailable" in launch_error_lower
            or "unshare:" in launch_error_lower
            or "trampoline" in launch_error_lower
            or "failed to execute" in launch_error_lower
            or "no such file or directory" in launch_error_lower
        )
    ):
        if sandbox_config is not None and "backend" in sandbox_config:
            pass
        else:
            import warnings

            warnings.warn(
                "Sandbox process creation failed. Falling back to weak SUBPROCESS backend due to allow_compat_fallback=True"
            )
            fallback_config = dict(sandbox_config or {})
            fallback_config["backend"] = SandboxBackend.SUBPROCESS
            fallback_config["allow_weak_backends"] = True
            result = _execute_with_config(_make_sandbox_config(fallback_config))

    if not result.succeeded:
        raise RuntimeError(result.get_stderr_text() or "Sandbox worker failed")
    return result.stdout


def extract_bytecode(
    source: bytes,
    filename: str,
    sandbox_config: Mapping[str, object] | None = None,
) -> BytecodeBlob:
    from pysymex._constants import SANDBOX_BLOCKED_MODULES

    worker = textwrap.dedent(
        f"""
        import marshal
        import sys

        _source = sys.stdin.buffer.read()
        _code = compile(_source, {filename!r}, "exec")
        _payload = marshal.dumps(_code)
        sys.stdout.buffer.write({_BYTECODE_MARKER!r} + _payload)
        """
    ).strip()

    cfg_overrides = dict(sandbox_config or {})
    cfg_overrides.setdefault("harness_restrict_builtins", False)
    cfg_overrides.setdefault("harness_install_audit_hook", True)
    cfg_overrides.setdefault("harness_block_ast_imports", False)
    cfg_overrides.setdefault("allow_compat_fallback", True)
    cfg_overrides.setdefault("harness_allowed_imports", frozenset({"marshal", "sys"}))
    cfg_overrides.setdefault(
        "harness_blocked_modules",
        SANDBOX_BLOCKED_MODULES.union({"json", "socket", "subprocess"}),
    )

    raw = _run_raw_worker(
        worker,
        sandbox_config=cfg_overrides,
        input_data=source,
    )
    if not raw.startswith(_BYTECODE_MARKER):
        raise RuntimeError("Missing bytecode marker")
    payload = raw[len(_BYTECODE_MARKER) :]
    return BytecodeBlob(
        payload=payload,
        filename=filename,
        producer_python=(sys.version_info.major, sys.version_info.minor),
    )


def execute_concrete(
    source: bytes,
    function_name: str,
    args: Mapping[str, object],
    *,
    filename: str = "_target.py",
    sandbox_config: Mapping[str, object] | None = None,
) -> ConcreteResult:
    import secrets

    from pysymex._constants import SANDBOX_BLOCKED_MODULES, SANDBOX_IMPORT_ALLOWLIST

    dynamic_marker = f"{_CONCRETE_MARKER}_{secrets.token_hex(16)}"

    worker = textwrap.dedent(
        f"""
        import json
        from pathlib import Path
        import sys
        import traceback

        _MARKER = {dynamic_marker!r}

        def _emit(payload):
            print(_MARKER + json.dumps(payload, ensure_ascii=True))

        _input = json.loads(sys.stdin.read() or "{{}}")
        _ns = {{}}
        try:
            _source_bytes = Path({filename!r}).read_bytes()
            exec(compile(_source_bytes, {filename!r}, "exec"), _ns)
            _fn = _ns.get({function_name!r})
            if not callable(_fn):
                raise ValueError("Target function not found or not callable")
            _ret = _fn(**dict(_input.get("args") or {{}}))
            json.dumps(_ret)
            _emit({{"ok": True, "return_value": _ret}})
        except Exception as _exc:
            _emit(
                {{
                    "ok": False,
                    "exception_type": type(_exc).__name__,
                    "exception_message": str(_exc),
                    "traceback": traceback.format_exc(),
                }}
            )
        """
    ).strip()

    cfg_overrides = dict(sandbox_config or {})
    cfg_overrides.setdefault("harness_restrict_builtins", False)
    cfg_overrides.setdefault("harness_install_audit_hook", True)
    cfg_overrides.setdefault("harness_block_ast_imports", False)
    cfg_overrides.setdefault(
        "harness_allowed_imports",
        SANDBOX_IMPORT_ALLOWLIST.union({"json", "pathlib", "sys", "traceback"}),
    )
    cfg_overrides.setdefault(
        "harness_blocked_modules",
        SANDBOX_BLOCKED_MODULES.union({"marshal", "socket", "subprocess"}),
    )

    payload = json.dumps({"args": dict(args)}).encode("utf-8")
    parsed, cleaned_stdout, stderr_text = _run_json_worker(
        worker,
        sandbox_config=cfg_overrides,
        extra_files={filename: source},
        input_data=payload,
        result_marker=dynamic_marker,
        fail_on_not_ok=False,
    )
    ok = _to_bool(parsed.get("ok", False), False)
    if ok:
        return ConcreteResult(
            succeeded=True,
            return_value=parsed.get("return_value"),
            stdout=cleaned_stdout,
            stderr=stderr_text,
        )
    return ConcreteResult(
        succeeded=False,
        exception_type=str(parsed.get("exception_type"))
        if parsed.get("exception_type") is not None
        else None,
        exception_message=str(parsed.get("exception_message"))
        if parsed.get("exception_message") is not None
        else None,
        traceback=str(parsed.get("traceback")) if parsed.get("traceback") is not None else None,
        stdout=cleaned_stdout,
        stderr=stderr_text,
    )


__all__ = [
    "BytecodeBlob",
    "ConcreteResult",
    "execute_concrete",
    "extract_bytecode",
]
