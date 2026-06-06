from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pysymex.sandbox.errors import SandboxSetupError
from pysymex.sandbox.isolation.wasm import WasmBackend, resolve_wasm_python_module
from pysymex.sandbox.types import ExecutionStatus, ResourceLimits, SandboxConfig


class _FakeWasmtimeConfig:
    consume_fuel: bool = False


class _FakeWasmtimeEngine:
    def __init__(self, config: _FakeWasmtimeConfig) -> None:
        self.config = config


class _FakeWasmtimeStore:
    def __init__(self, engine: _FakeWasmtimeEngine) -> None:
        self.engine = engine
        self.fuel = 0
        self.memory_size = 0
        self.wasi: _FakeWasiConfig | None = None

    def set_limits(
        self,
        *,
        memory_size: int,
        instances: int,
        memories: int,
        tables: int,
        table_elements: int,
    ) -> None:
        _ = instances
        _ = memories
        _ = tables
        _ = table_elements
        self.memory_size = memory_size

    def set_fuel(self, fuel: int) -> None:
        self.fuel = fuel

    def set_wasi(self, wasi: "_FakeWasiConfig") -> None:
        self.wasi = wasi


class _FakeWasiConfig:
    def __init__(self) -> None:
        self.argv: list[str] = []
        self.env: list[tuple[str, str]] = []
        self.stdin_file = ""
        self.stdout_file = ""
        self.stderr_file = ""
        self.preopens: list[tuple[str, str]] = []

    def preopen_dir(self, host_path: str, guest_path: str) -> None:
        self.preopens.append((host_path, guest_path))


class _FakeWasmtimeModule:
    @classmethod
    def from_file(cls, engine: _FakeWasmtimeEngine, path: str) -> "_FakeWasmtimeModule":
        _ = engine
        _ = path
        return cls()


class _FakeWasmtimeInstance:
    def __init__(self, output: bytes) -> None:
        self.output = output

    def exports(self, store: _FakeWasmtimeStore) -> dict[str, object]:
        def _start(inner_store: _FakeWasmtimeStore) -> None:
            assert inner_store.wasi is not None
            Path(inner_store.wasi.stdout_file).write_bytes(self.output)

        _ = store
        return {"_start": _start}


class _FakeWasmtimeLinker:
    output: bytes = b"wasm-ok\n"

    def __init__(self, engine: _FakeWasmtimeEngine) -> None:
        self.engine = engine
        self.wasi_defined = False

    def define_wasi(self) -> None:
        self.wasi_defined = True

    def instantiate(
        self,
        store: _FakeWasmtimeStore,
        module: _FakeWasmtimeModule,
    ) -> _FakeWasmtimeInstance:
        _ = store
        _ = module
        assert self.wasi_defined is True
        return _FakeWasmtimeInstance(self.output)


def _fake_wasmtime_module(output: bytes = b"wasm-ok\n") -> SimpleNamespace:
    class Linker(_FakeWasmtimeLinker):
        pass

    Linker.output = output
    return SimpleNamespace(
        Config=_FakeWasmtimeConfig,
        Engine=_FakeWasmtimeEngine,
        Store=_FakeWasmtimeStore,
        WasiConfig=_FakeWasiConfig,
        Linker=Linker,
        Module=_FakeWasmtimeModule,
    )


class TestWasmBackend:
    """Test suite for pysymex.sandbox.isolation.wasm.WasmBackend."""

    @pytest.mark.timeout(30)
    def test_resolve_wasm_python_module_requires_existing_file(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.wasm"
        assert resolve_wasm_python_module(SandboxConfig(wasm_python_module=missing)) is None

        artifact = tmp_path / "python.wasm"
        artifact.write_bytes(b"\0asm")
        assert resolve_wasm_python_module(SandboxConfig(wasm_python_module=artifact)) == artifact

    @pytest.mark.timeout(30)
    def test_is_available_requires_wasmtime_and_python_artifact(self, tmp_path: Path) -> None:
        artifact = tmp_path / "python.wasm"
        artifact.write_bytes(b"\0asm")
        backend = WasmBackend(SandboxConfig(wasm_python_module=artifact))

        with patch("pysymex.sandbox.isolation.wasm.runtime.find_spec", return_value=None):
            assert backend.is_available is False

        with patch("pysymex.sandbox.isolation.wasm.runtime.find_spec", return_value=object()):
            assert backend.is_available is True

    @pytest.mark.timeout(30)
    def test_get_capabilities_reports_strong_wasi_boundary(self) -> None:
        backend = WasmBackend(SandboxConfig())
        caps = backend.get_capabilities()
        assert caps.process_isolation is True
        assert caps.filesystem_jail is True
        assert caps.network_blocking is True
        assert caps.syscall_filtering is True
        assert caps.memory_limits is True
        assert caps.cpu_limits is True
        assert caps.process_limits is True

    @pytest.mark.timeout(30)
    def test_setup_fails_closed_without_wasmtime(self, tmp_path: Path) -> None:
        artifact = tmp_path / "python.wasm"
        artifact.write_bytes(b"\0asm")
        backend = WasmBackend(SandboxConfig(wasm_python_module=artifact))

        with patch("pysymex.sandbox.isolation.wasm.backend.find_spec", return_value=None):
            with pytest.raises(SandboxSetupError, match="wasmtime"):
                backend.setup()

    @pytest.mark.timeout(30)
    def test_setup_fails_closed_without_python_artifact(self) -> None:
        backend = WasmBackend(SandboxConfig())

        with patch("pysymex.sandbox.isolation.wasm.backend.find_spec", return_value=object()):
            with pytest.raises(SandboxSetupError, match="WASI Python"):
                backend.setup()

    @pytest.mark.timeout(30)
    def test_execute_without_setup_fails(self) -> None:
        backend = WasmBackend(SandboxConfig())
        with pytest.raises(SandboxSetupError):
            backend.execute(b"print('x')", "x.py", b"", {})

    @pytest.mark.timeout(30)
    def test_execute_runs_wasi_python_without_native_subprocess(self, tmp_path: Path) -> None:
        artifact = tmp_path / "python.wasm"
        artifact.write_bytes(b"\0asm")
        config = SandboxConfig(
            wasm_python_module=artifact,
            limits=ResourceLimits(timeout_seconds=1.0, cpu_seconds=1, memory_mb=32),
            environment={"PYTHONHASHSEED": "0"},
        )
        backend = WasmBackend(config)

        with (
            patch("pysymex.sandbox.isolation.wasm.backend.find_spec", return_value=object()),
            patch(
                "pysymex.sandbox.isolation.wasm.backend.import_module",
                return_value=_fake_wasmtime_module(),
            ),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('ok')\n", "target.py", b"input", {})
            finally:
                backend.cleanup()

        assert result.status is ExecutionStatus.SUCCESS
        assert result.exit_code == 0
        assert result.get_stdout_text() == "wasm-ok\n"

    @pytest.mark.timeout(30)
    def test_execute_enforces_output_limit(self, tmp_path: Path) -> None:
        artifact = tmp_path / "python.wasm"
        artifact.write_bytes(b"\0asm")
        config = SandboxConfig(
            wasm_python_module=artifact,
            limits=ResourceLimits(max_output_bytes=4),
        )
        backend = WasmBackend(config)

        with (
            patch("pysymex.sandbox.isolation.wasm.backend.find_spec", return_value=object()),
            patch(
                "pysymex.sandbox.isolation.wasm.backend.import_module",
                return_value=_fake_wasmtime_module(b"too much output"),
            ),
        ):
            backend.setup()
            try:
                result = backend.execute(b"print('x')\n", "target.py", b"", {})
            finally:
                backend.cleanup()

        assert result.status is ExecutionStatus.SECURITY_VIOLATION
        assert result.blocked_operations == ["output-limit"]
        assert result.stdout == b"too "
