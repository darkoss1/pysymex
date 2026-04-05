"""Adversarial escape regression tests for the sandbox module."""

from __future__ import annotations

import marshal
from pathlib import Path
from typing import Any
import sys
import subprocess

import pytest

from pysymex.sandbox import SandboxBackend, SandboxConfig, SecureSandbox
from pysymex.sandbox._types import SecurityCapabilities
from pysymex.sandbox._errors import SandboxSetupError
from pysymex.sandbox import bridge as sandbox_bridge
from pysymex.sandbox.isolation._harness import generate_harness_script
from pysymex.sandbox.isolation.linux import LinuxNamespaceBackend
from pysymex.sandbox.isolation.windows import WindowsJobBackend


def test_execute_code_rejects_extra_file_traversal(tmp_path: Path):
    config = SandboxConfig(
        backend=SandboxBackend.SUBPROCESS,
        working_directory=tmp_path,
        allow_weak_backends=True,
    )

    payload_paths = [
        "../escape.txt",
        "..\\escape.txt",
        "/tmp/escape.txt",
        "C:/escape.txt",
        "C:\\escape.txt",
        "./../x.py",
        "-hidden/evil.py",
    ]

    with SecureSandbox(config) as sandbox:
        for rel_path in payload_paths:
            with pytest.raises(ValueError):
                sandbox.execute_code(
                    "print('x')",
                    extra_files={rel_path: b"owned"},
                )


def test_execute_code_allows_nested_relative_extra_files(tmp_path: Path):
    config = SandboxConfig(
        backend=SandboxBackend.SUBPROCESS,
        working_directory=tmp_path,
        allow_weak_backends=True,
    )

    code = "print('ok')"

    with SecureSandbox(config) as sandbox:
        result = sandbox.execute_code(
            code,
            extra_files={"inputs/data.txt": b"safe"},
        )

    assert result.succeeded
    assert "ok" in result.get_stdout_text()


def test_detect_best_backend_darwin_falls_back_when_sandbox_exec_missing(monkeypatch: Any):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("pysymex.sandbox.runner._check_macos_sandbox_support", lambda: False)
    monkeypatch.setattr("pysymex.sandbox.runner._check_wasm_support", lambda: False)

    cfg = SandboxConfig(allow_weak_backends=True)
    with SecureSandbox(cfg) as sandbox:
        assert sandbox.backend_name == "SubprocessBackend"


def test_fail_closed_rejects_weak_backend_by_default(monkeypatch: Any):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("pysymex.sandbox.runner._check_macos_sandbox_support", lambda: False)
    monkeypatch.setattr("pysymex.sandbox.runner._check_wasm_support", lambda: False)

    with pytest.raises(SandboxSetupError):
        with SecureSandbox():
            pass


def test_capability_contract_rejects_backend_missing_network_block(tmp_path: Path):
    cfg = SandboxConfig(
        backend=SandboxBackend.SUBPROCESS,
        working_directory=tmp_path,
        allow_weak_backends=True,
        required_capabilities=SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=True,
            network_blocking=True,
        ),
    )

    with pytest.raises(SandboxSetupError):
        with SecureSandbox(cfg):
            pass


def test_capability_contract_allows_matching_requirements(tmp_path: Path):
    cfg = SandboxConfig(
        backend=SandboxBackend.SUBPROCESS,
        working_directory=tmp_path,
        allow_weak_backends=True,
        required_capabilities=SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=True,
        ),
    )

    with SecureSandbox(cfg) as sandbox:
        assert sandbox.backend_name == "SubprocessBackend"


def test_extract_bytecode_fail_closed_on_backend_setup_error(monkeypatch: Any):
    class _FailingSecureSandbox:
        def __init__(self, _cfg: Any) -> None:
            self.cfg = _cfg

        def __enter__(self) -> Any:
            raise RuntimeError("setup failed")

        def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            return None

    monkeypatch.setattr("pysymex.sandbox.SecureSandbox", _FailingSecureSandbox)

    with pytest.raises(RuntimeError):
        sandbox_bridge.extract_bytecode(
            b"def f(x):\n    return x + 1\n",
            "target.py",
        )


def test_execute_concrete_returns_exception_payload_for_runtime_error() -> None:
    result = sandbox_bridge.execute_concrete(
        b"def f(x):\n    return 10 // x\n",
        "f",
        {"x": 0},
        sandbox_config={"allow_compat_fallback": True},
    )
    assert result.succeeded is False
    assert result.exception_type is not None
    assert "division" in (result.exception_message or "").lower()


def test_linux_capabilities_match_unshare_mode(monkeypatch: Any):
    cfg = SandboxConfig()
    backend = LinuxNamespaceBackend(cfg)

    def _which_has_unshare(cmd: str) -> str | None:
        return "/usr/bin/unshare" if cmd == "unshare" else None

    monkeypatch.setattr("shutil.which", _which_has_unshare)
    monkeypatch.setattr(
        LinuxNamespaceBackend,
        "_supports_unshare_root",
        staticmethod(lambda: True),
    )
    caps_unshare = backend.get_capabilities()
    assert caps_unshare.network_blocking is True
    assert caps_unshare.filesystem_jail is True
    assert caps_unshare.syscall_filtering is True

    def _which_missing(_cmd: str) -> None:
        return None

    monkeypatch.setattr("shutil.which", _which_missing)
    caps_fallback = backend.get_capabilities()
    assert caps_fallback.network_blocking is False
    assert caps_fallback.filesystem_jail is False
    assert caps_fallback.syscall_filtering is False


def test_windows_is_available_fails_closed_on_platform_probe_error(monkeypatch: Any):
    cfg = SandboxConfig(backend=SandboxBackend.WINDOWS_JOB)
    backend = WindowsJobBackend(cfg)

    monkeypatch.setattr(sys, "platform", "win32")

    def _raise_release() -> str:
        raise RuntimeError("probe failed")

    monkeypatch.setattr("platform.release", _raise_release)

    assert backend.is_available is False


def test_windows_setup_failure_cleans_up_jail(tmp_path: Path, monkeypatch: Any) -> None:
    cfg = SandboxConfig(backend=SandboxBackend.WINDOWS_JOB, working_directory=tmp_path)
    backend = WindowsJobBackend(cfg)

    monkeypatch.setattr(
        WindowsJobBackend,
        "is_available",
        property(lambda _self: True),
    )

    jail = tmp_path / "pysymex_sandbox_test"

    def _create_jail() -> Path:
        jail.mkdir(parents=True, exist_ok=False)
        return jail

    monkeypatch.setattr(backend, "_create_jail", _create_jail)

    def _raise_job_create() -> object:
        raise RuntimeError("job create failed")

    monkeypatch.setattr(backend, "_create_configured_job_object", _raise_job_create)

    with pytest.raises(SandboxSetupError):
        backend.setup()

    assert not jail.exists()
    assert backend.jail_path is None


def test_execute_code_rejects_oversized_extra_file(tmp_path: Path):
    config = SandboxConfig(
        backend=SandboxBackend.SUBPROCESS,
        working_directory=tmp_path,
        allow_weak_backends=True,
    )

    over_limit = (config.limits.max_file_size_mb * 1024 * 1024) + 1
    payload = b"x" * over_limit
    with SecureSandbox(config) as sandbox:
        with pytest.raises(ValueError):
            sandbox.execute_code("print('x')", extra_files={"data.bin": payload})


def test_subprocess_backend_uses_python_isolated_mode_flags(tmp_path: Path, monkeypatch: Any):
    config = SandboxConfig(
        backend=SandboxBackend.SUBPROCESS,
        working_directory=tmp_path,
        allow_weak_backends=True,
    )

    captured_cmd: list[str] = []

    class _FakePopen:
        def __init__(self, cmd: list[str], **kwargs: Any) -> None:
            captured_cmd.extend(cmd)
            self.returncode = 0

        def communicate(self, input: bytes | None = None, timeout: float | None = None) -> tuple[bytes, bytes]:
            return (b"ok\n", b"")

        def kill(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return 0

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)

    with SecureSandbox(config) as sandbox:
        result = sandbox.execute_code("print('ok')")

    assert result.succeeded
    assert "-I" in captured_cmd
    assert "-B" in captured_cmd


def test_bridge_config_enforces_strict_harness_by_default() -> None:
    cfg = sandbox_bridge._make_sandbox_config({})  # pyright: ignore[reportPrivateUsage]
    assert cfg.backend is None
    assert cfg.allow_weak_backends is False
    assert cfg.harness_restrict_builtins is True
    assert cfg.harness_install_audit_hook is True
    assert cfg.harness_block_ast_imports is True
    assert cfg.harness_blocked_modules is None


def test_bridge_config_accepts_explicit_worker_module_policy() -> None:
    cfg = sandbox_bridge._make_sandbox_config(  # pyright: ignore[reportPrivateUsage]
        {
            "harness_blocked_modules": frozenset({"socket", "subprocess"}),
        }
    )
    assert cfg.harness_restrict_builtins is True
    assert cfg.harness_install_audit_hook is True
    assert cfg.harness_blocked_modules == frozenset({"socket", "subprocess"})


def test_harness_audit_hook_blocks_ctypes_runtime_events(tmp_path: Path):
    config = SandboxConfig(
        backend=SandboxBackend.SUBPROCESS,
        working_directory=tmp_path,
        allow_weak_backends=True,
        harness_blocked_modules=frozenset(),
        harness_restrict_builtins=False,
        harness_install_audit_hook=True,
        harness_block_ast_imports=False,
    )

    code = "import ctypes\nctypes.CDLL(None)\n"

    with SecureSandbox(config) as sandbox:
        result = sandbox.execute_code(code)

    assert not result.succeeded
    err = result.get_stderr_text() + result.get_stdout_text()
    assert "blocked runtime event" in err


def test_harness_ast_import_blocking_rejects_import_statements(tmp_path: Path):
    config = SandboxConfig(
        backend=SandboxBackend.SUBPROCESS,
        working_directory=tmp_path,
        allow_weak_backends=True,
        harness_blocked_modules=frozenset(),
        harness_restrict_builtins=False,
        harness_install_audit_hook=False,
        harness_block_ast_imports=True,
    )

    code = "import math\nprint(math.sqrt(4))\n"

    with SecureSandbox(config) as sandbox:
        result = sandbox.execute_code(code)

    assert not result.succeeded
    err = result.get_stderr_text() + result.get_stdout_text()
    assert "import statements are disabled" in err


def test_extract_bytecode_roundtrip_returns_code_object() -> None:
    blob = sandbox_bridge.extract_bytecode(
        b"def f(x):\n    return x + 1\n",
        "target.py",
        sandbox_config={"allow_compat_fallback": True},
    )
    assert isinstance(blob, sandbox_bridge.BytecodeBlob)
    code_obj = blob.reconstruct()
    assert hasattr(code_obj, "co_consts")
    assert code_obj.co_filename == "target.py"


def test_extract_bytecode_missing_marker_fails_closed(monkeypatch: Any) -> None:
    def _invalid_raw_worker(*_args: object, **_kwargs: object) -> bytes:
        return b"invalid"

    monkeypatch.setattr(
        sandbox_bridge,
        "_run_raw_worker",
        _invalid_raw_worker,
    )

    with pytest.raises(RuntimeError):
        sandbox_bridge.extract_bytecode(
            b"def f(x):\n    return x + 1\n",
            "target.py",
        )


def test_bytecode_blob_rejects_corrupted_payload() -> None:
    blob = sandbox_bridge.extract_bytecode(
        b"def f(x):\n    return x + 1\n",
        "target.py",
        sandbox_config={"allow_compat_fallback": True},
    )
    bad_blob = sandbox_bridge.BytecodeBlob(
        payload=b"not-a-marshal-payload",
        filename=blob.filename,
        producer_python=blob.producer_python,
    )

    with pytest.raises(ValueError):
        bad_blob.reconstruct()


def test_bytecode_blob_rejects_oversized_payload() -> None:
    max_size = sandbox_bridge._MAX_BYTECODE_PAYLOAD_BYTES  # pyright: ignore[reportPrivateUsage]
    blob = sandbox_bridge.BytecodeBlob(
        payload=b"x" * (max_size + 1),
        filename="target.py",
        producer_python=None,
    )
    with pytest.raises(ValueError):
        blob.reconstruct()


def test_bytecode_blob_rejects_unexpected_filename_metadata() -> None:
    forged_code = compile("x = 1", "forged.py", "exec")
    blob = sandbox_bridge.BytecodeBlob(
        payload=marshal.dumps(forged_code),
        filename="target.py",
        producer_python=(sys.version_info.major, sys.version_info.minor),
    )
    with pytest.raises(ValueError):
        blob.reconstruct()


def test_execute_concrete_success_payload() -> None:
    result = sandbox_bridge.execute_concrete(
        b"def f(x):\n    return x + 1\n",
        "f",
        {"x": 2},
        sandbox_config={"allow_compat_fallback": True},
    )
    assert result.succeeded is True
    assert result.return_value == 3


def test_execute_concrete_preserves_source_bytes_encoding_cookie() -> None:
    src = b"# coding: latin-1\n\ndef f():\n    return 'caf\xe9'\n"
    result = sandbox_bridge.execute_concrete(
        src,
        "f",
        {},
        sandbox_config={"allow_compat_fallback": True},
    )
    assert result.succeeded is True
    assert result.return_value == "caf\u00e9"


def test_generate_harness_places_seccomp_before_import_blocker() -> None:
    script = generate_harness_script(
        install_seccomp=True,
        seccomp_allowlist=(0, 1, 2),
    )
    seccomp_idx = script.find("_PR_SET_SECCOMP")
    blocker_idx = script.find("class _StrictModuleBlocker")
    assert seccomp_idx != -1
    assert blocker_idx != -1
    assert seccomp_idx < blocker_idx
