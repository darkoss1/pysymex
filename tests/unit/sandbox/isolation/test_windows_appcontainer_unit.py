import hashlib
import json
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from pysymex._internal.config.sandbox.types import SandboxConfig
from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.appcontainer.backend import (
    AppContainerBackend,
    has_windows_appcontainer_support,
)
from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import (
    RUNTIME_CACHE_POLICY_VERSION,
)
from tests.unit.sandbox.isolation.windows_appcontainer_helpers import (
    InspectableWindowsAppContainerBackend,
)


class TestWindowsAppContainerBackend:
    @pytest.mark.timeout(30)
    def test_support_probe_is_false_off_windows(self) -> None:
        with patch("pysymex._internal.sandbox.isolation.windows.native.api.sys.platform", "linux"):
            assert has_windows_appcontainer_support() is False

    @pytest.mark.timeout(30)
    def test_setup_fails_closed_when_appcontainer_apis_are_unavailable(self) -> None:
        backend = AppContainerBackend(SandboxConfig())
        with (
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.backend.has_windows_native_appcontainer_support",
                return_value=False,
            ),
            pytest.raises(SandboxSetupError, match="AppContainer APIs"),
        ):
            backend.setup()

    @pytest.mark.timeout(30)
    def test_capabilities_are_unverified_before_setup(self) -> None:
        backend = InspectableWindowsAppContainerBackend(SandboxConfig())

        caps = backend.get_capabilities()

        assert caps.process_isolation is False
        assert caps.filesystem_jail is False
        assert caps.network_blocking is False
        assert caps.memory_limits is False
        assert caps.cpu_limits is False
        assert caps.process_limits is False
        assert caps.syscall_filtering is False

    @pytest.mark.timeout(30)
    def test_capabilities_are_strong_after_security_self_check(self) -> None:
        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        backend.mark_verified_for_test()

        caps = backend.get_capabilities()

        assert caps.process_isolation is True
        assert caps.filesystem_jail is True
        assert caps.network_blocking is True
        assert caps.memory_limits is True
        assert caps.cpu_limits is True
        assert caps.process_limits is True
        assert caps.syscall_filtering is False

    @pytest.mark.timeout(30)
    def test_appcontainer_job_process_limit_is_always_one(self) -> None:
        assert AppContainerBackend.effective_active_process_limit(0) == 1
        assert AppContainerBackend.effective_active_process_limit(1) == 1
        assert AppContainerBackend.effective_active_process_limit(4) == 1

    @pytest.mark.timeout(30)
    def test_win32_ctypes_bindings_stay_in_native_helper(self) -> None:
        """Keep raw Win32 structure layouts out of AppContainer orchestration."""
        root = Path(__file__).resolve().parents[4]
        orchestration = (
            root
            / "pysymex"
            / "_internal"
            / "sandbox"
            / "isolation"
            / "windows"
            / "appcontainer"
            / "backend.py"
        )
        native_api = (
            root
            / "pysymex"
            / "_internal"
            / "sandbox"
            / "isolation"
            / "windows"
            / "native"
            / "api.py"
        )
        native_shared = (
            root
            / "pysymex"
            / "_internal"
            / "sandbox"
            / "isolation"
            / "windows"
            / "native"
            / "shared.py"
        )

        orchestration_source = orchestration.read_text(encoding="utf-8")
        native_api_source = native_api.read_text(encoding="utf-8")
        native_shared_source = native_shared.read_text(encoding="utf-8")

        assert "\nimport ctypes\n" not in f"\n{orchestration_source}"
        assert "\nfrom ctypes import" not in f"\n{orchestration_source}"
        assert "ctypes.Structure" not in orchestration_source
        assert "ctypes.Structure" in native_shared_source
        assert "class WindowsNativeApi" in native_api_source

    @pytest.mark.timeout(30)
    def test_stages_cached_python_runtime_without_site_packages(self, tmp_path: Path) -> None:
        source_root = tmp_path / "source"
        source_root.mkdir()
        (source_root / "python.exe").write_bytes(b"exe")
        (source_root / "python313.dll").write_bytes(b"dll")
        (source_root / "Lib").mkdir()
        (source_root / "Lib" / "encodings").mkdir()
        (source_root / "Lib" / "encodings" / "__init__.py").write_text("", encoding="utf-8")
        (source_root / "Lib" / "site-packages").mkdir()
        (source_root / "Lib" / "site-packages" / "host_only.py").write_text(
            "",
            encoding="utf-8",
        )
        (source_root / "Lib" / "module.pyc").write_bytes(b"cached")
        (source_root / "DLLs").mkdir()
        (source_root / "DLLs" / "_decimal.pyd").write_bytes(b"pyd")
        (source_root / "DLLs" / "_ctypes.pyd").write_bytes(b"ctypes")
        (source_root / "DLLs" / "_socket.pyd").write_bytes(b"socket")
        (source_root / "DLLs" / "_testcapi.pyd").write_bytes(b"test")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        jail_path = tmp_path / "jail"
        cache_root = tmp_path / "cache"
        jail_path.mkdir()
        backend.set_jail_path_for_test(jail_path)
        grant_calls: list[tuple[Path, bool]] = []

        def record_runtime_grant(path: Path, *, recursive: bool) -> None:
            grant_calls.append((path, recursive))

        with (
            patch.object(backend, "_python_runtime_source_root", return_value=source_root),
            patch.object(backend, "_runtime_cache_root", return_value=cache_root),
            patch.object(backend, "_grant_runtime_cache_access", side_effect=record_runtime_grant),
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.runtime.build.sys.platform",
                "win32",
            ),
            patch(
                "pysymex._internal.sandbox.isolation.windows.appcontainer.runtime.runtime_cache.sys.platform",
                "win32",
            ),
        ):
            backend.stage_python_runtime_for_test()

        runtime = backend.runtime_path_for_test()
        assert runtime is not None
        assert len(grant_calls) == 2
        assert grant_calls[0][0].name.startswith(f".{runtime.name}.")
        assert grant_calls[0][1] is False
        assert grant_calls[1] == (runtime, True)
        assert cache_root in runtime.parents
        assert jail_path not in runtime.parents
        assert (runtime / "python.exe").read_bytes() == b"exe"
        assert (runtime / "python313.dll").read_bytes() == b"dll"
        assert (runtime / "Lib" / "encodings" / "__init__.py").is_file()
        assert (runtime / ".pysymex-runtime-manifest.json").is_file()
        assert not (runtime / "Lib" / "site-packages").exists()
        assert not (runtime / "Lib" / "module.pyc").exists()
        assert not (runtime / "DLLs" / "_decimal.pyd").exists()
        assert not (runtime / "DLLs" / "_ctypes.pyd").exists()
        assert not (runtime / "DLLs" / "_socket.pyd").exists()
        assert not (runtime / "DLLs" / "_testcapi.pyd").exists()

        manifest_obj = json.loads((runtime / ".pysymex-runtime-manifest.json").read_text())
        assert isinstance(manifest_obj, dict)
        manifest = cast("dict[str, object]", manifest_obj)
        assert manifest["policy"] == RUNTIME_CACHE_POLICY_VERSION
        manifest_files_obj = manifest["files"]
        assert isinstance(manifest_files_obj, list)
        manifest_files = cast("list[object]", manifest_files_obj)
        python_entry: dict[str, object] | None = None
        for entry_obj in manifest_files:
            if not isinstance(entry_obj, dict):
                continue
            entry = cast("dict[str, object]", entry_obj)
            if entry.get("path") == "python.exe":
                python_entry = entry
                break
        assert python_entry is not None
        assert "sha256" not in python_entry
        with (source_root / "python.exe").open("rb") as executable:
            expected_digest = hashlib.file_digest(executable, "sha512_256").hexdigest()
        assert python_entry["digest"] == expected_digest

    @pytest.mark.timeout(30)
    def test_runtime_cache_manifest_mismatch_rebuilds_from_source(self, tmp_path: Path) -> None:
        source_root = tmp_path / "source"
        source_root.mkdir()
        (source_root / "python.exe").write_bytes(b"exe")
        (source_root / "Lib").mkdir()
        (source_root / "Lib" / "module.py").write_text("value = 1\n", encoding="utf-8")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        jail_path = tmp_path / "jail"
        cache_root = tmp_path / "cache"
        jail_path.mkdir()
        backend.set_jail_path_for_test(jail_path)

        with (
            patch.object(backend, "_python_runtime_source_root", return_value=source_root),
            patch.object(backend, "_runtime_cache_root", return_value=cache_root),
        ):
            backend.stage_python_runtime_for_test()
            first_runtime = backend.runtime_path_for_test()
            assert first_runtime is not None
            cached_module = first_runtime / "Lib" / "module.py"
            tampered_source = "value = 2\n"
            assert len(tampered_source) == len("value = 1\n")
            cached_module.write_text(tampered_source, encoding="utf-8")

            backend.stage_python_runtime_for_test()

        second_runtime = backend.runtime_path_for_test()
        assert second_runtime == first_runtime
        assert cached_module.read_text(encoding="utf-8") == "value = 1\n"

    @pytest.mark.timeout(30)
    def test_runtime_cache_rename_retries_transient_permission_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        temp_path = tmp_path / ".runtime.tmp"
        runtime_path = tmp_path / "runtime"
        temp_path.mkdir()
        calls = 0
        original_rename = Path.rename

        def flaky_rename(self: Path, target: str | Path) -> Path:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise PermissionError("transient lock")
            return original_rename(self, target)

        monkeypatch.setattr(Path, "rename", flaky_rename)

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        with patch(
            "pysymex._internal.sandbox.isolation.windows.appcontainer.runtime.build.sys.platform",
            "win32",
        ):
            backend.rename_runtime_cache_for_test(temp_path, runtime_path)

        assert calls == 2
        assert runtime_path.is_dir()

    @pytest.mark.timeout(30)
    def test_runtime_cache_ignores_generated_pycache_when_reusing_cache(
        self,
        tmp_path: Path,
    ) -> None:
        source_root = tmp_path / "source"
        source_root.mkdir()
        (source_root / "python.exe").write_bytes(b"exe")
        (source_root / "Lib").mkdir()
        (source_root / "Lib" / "module.py").write_text("value = 1\n", encoding="utf-8")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        jail_path = tmp_path / "jail"
        cache_root = tmp_path / "cache"
        jail_path.mkdir()
        backend.set_jail_path_for_test(jail_path)

        with (
            patch.object(backend, "_python_runtime_source_root", return_value=source_root),
            patch.object(backend, "_runtime_cache_root", return_value=cache_root),
        ):
            backend.stage_python_runtime_for_test()
            first_runtime = backend.runtime_path_for_test()
            assert first_runtime is not None
            pycache = first_runtime / "Lib" / "__pycache__"
            pycache.mkdir()
            bytecode_cache = pycache / "module.cpython-311.pyc"
            bytecode_cache.write_bytes(b"generated")

            with patch.object(
                backend,
                "_remove_cache_tree",
                side_effect=AssertionError("runtime cache should be reused"),
            ):
                backend.stage_python_runtime_for_test()

        assert backend.runtime_path_for_test() == first_runtime
        assert not bytecode_cache.exists()
        assert not pycache.exists()

    @pytest.mark.timeout(30)
    def test_runtime_cache_rebuilds_when_pycache_contains_unexpected_file(
        self,
        tmp_path: Path,
    ) -> None:
        source_root = tmp_path / "source"
        source_root.mkdir()
        (source_root / "python.exe").write_bytes(b"exe")
        (source_root / "Lib").mkdir()
        (source_root / "Lib" / "module.py").write_text("value = 1\n", encoding="utf-8")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        jail_path = tmp_path / "jail"
        cache_root = tmp_path / "cache"
        jail_path.mkdir()
        backend.set_jail_path_for_test(jail_path)

        with (
            patch.object(backend, "_python_runtime_source_root", return_value=source_root),
            patch.object(backend, "_runtime_cache_root", return_value=cache_root),
        ):
            backend.stage_python_runtime_for_test()
            first_runtime = backend.runtime_path_for_test()
            assert first_runtime is not None
            pycache = first_runtime / "Lib" / "__pycache__"
            pycache.mkdir()
            unexpected = pycache / "unexpected.txt"
            unexpected.write_text("not generated bytecode", encoding="utf-8")

            backend.stage_python_runtime_for_test()

        second_runtime = backend.runtime_path_for_test()
        assert second_runtime == first_runtime
        assert not unexpected.exists()
        assert not pycache.exists()

    @pytest.mark.timeout(30)
    def test_runtime_cache_source_scan_does_not_follow_symlinks(self, tmp_path: Path) -> None:
        source_root = tmp_path / "source"
        external_root = tmp_path / "external"
        source_root.mkdir()
        external_root.mkdir()
        (source_root / "python.exe").write_bytes(b"exe")
        (source_root / "Lib").mkdir()
        (source_root / "Lib" / "safe.py").write_text("safe = True\n", encoding="utf-8")
        secret = external_root / "secret.py"
        secret.write_text("secret = True\n", encoding="utf-8")
        try:
            (source_root / "Lib" / "leak.py").symlink_to(secret)
        except OSError as exc:
            pytest.skip(f"symlinks unavailable on this host: {exc}")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        jail_path = tmp_path / "jail"
        cache_root = tmp_path / "cache"
        jail_path.mkdir()
        backend.set_jail_path_for_test(jail_path)

        with (
            patch.object(backend, "_python_runtime_source_root", return_value=source_root),
            patch.object(backend, "_runtime_cache_root", return_value=cache_root),
        ):
            backend.stage_python_runtime_for_test()

        runtime = backend.runtime_path_for_test()
        assert runtime is not None
        assert (runtime / "Lib" / "safe.py").is_file()
        assert not (runtime / "Lib" / "leak.py").exists()
