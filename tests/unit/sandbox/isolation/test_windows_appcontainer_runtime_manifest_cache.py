import hashlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import pysymex._internal.sandbox.isolation.windows.appcontainer.runtime.runtime_cache as runtime_module
from pysymex._internal.config.sandbox.types import SandboxConfig
from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.appcontainer.runtime.cache import (
    RuntimeManifestEntry as _RuntimeManifestEntry,
)
from pysymex._internal.sandbox.isolation.windows.appcontainer.runtime.cache import (
    build_runtime_manifest_entries,
)
from tests.unit.sandbox.isolation.windows_appcontainer_helpers import (
    InspectableWindowsAppContainerBackend,
)


def _write_minimal_runtime(source_root: Path, module_source: str) -> Path:
    source_root.mkdir()
    (source_root / "python.exe").write_bytes(b"exe")
    (source_root / "Lib").mkdir()
    module = source_root / "Lib" / "module.py"
    module.write_text(module_source, encoding="utf-8")
    return module


def _find_manifest_index_file(
    backend: InspectableWindowsAppContainerBackend, source_root: Path
) -> Path:
    cache_root = backend._runtime_cache_root()  # pyright: ignore[reportPrivateUsage]
    cache_key = source_root.resolve()
    safe_key = hashlib.new("sha512_256", str(cache_key).encode("utf-8")).hexdigest()[:32]
    return cache_root / f"manifest_index_{safe_key}.json"


class TestWindowsAppContainerRuntimeManifestCache:
    @pytest.mark.timeout(30)
    def test_manifest_cache_invalidates_when_source_file_changes(
        self,
        tmp_path: Path,
    ) -> None:
        source_root = tmp_path / "source"
        module = _write_minimal_runtime(source_root, "value = 1\n")
        cache_root = tmp_path / "cache"
        jail_path = tmp_path / "jail"
        jail_path.mkdir()

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        backend.set_jail_path_for_test(jail_path)
        with (
            patch.object(backend, "_python_runtime_source_root", return_value=source_root),
            patch.object(backend, "_runtime_cache_root", return_value=cache_root),
        ):
            backend.stage_python_runtime_for_test()
            first_runtime = backend.runtime_path_for_test()
            assert first_runtime is not None

            old_mtime = module.stat().st_mtime_ns
            module.write_text("value = 2\n", encoding="utf-8")
            module_stat = module.stat()
            os.utime(
                module,
                ns=(
                    module_stat.st_atime_ns,
                    max(module_stat.st_mtime_ns, old_mtime) + 1_000_000_000,
                ),
            )
            assert module.stat().st_mtime_ns != old_mtime

            backend.stage_python_runtime_for_test()

        second_runtime = backend.runtime_path_for_test()
        assert second_runtime is not None
        assert second_runtime != first_runtime
        staged_module = second_runtime / "Lib" / "module.py"
        assert staged_module.read_text(encoding="utf-8") == "value = 2\n"

    @pytest.mark.timeout(30)
    def test_manifest_cache_reuses_unchanged_source_snapshot(self, tmp_path: Path) -> None:
        source_root = tmp_path / "source"
        _write_minimal_runtime(source_root, "value = 1\n")
        backend = InspectableWindowsAppContainerBackend(SandboxConfig())

        with patch.object(
            runtime_module,
            "build_runtime_manifest_entries",
            wraps=build_runtime_manifest_entries,
        ) as build_manifest:
            first_entries = backend.runtime_source_manifest_for_test(source_root)
            second_entries = backend.runtime_source_manifest_for_test(source_root)

        assert first_entries == second_entries
        assert first_entries is not second_entries
        assert build_manifest.call_count == 1

    @pytest.mark.timeout(30)
    def test_runtime_manifest_uses_disk_cache_on_fresh_process(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        source_root = tmp_path / "runtime"
        (source_root / "Lib").mkdir(parents=True)
        (source_root / "Lib" / "a.py").write_text("x = 1", encoding="utf-8")
        (source_root / "Lib" / "b.py").write_text("y = 2", encoding="utf-8")
        (source_root / "python.exe").write_bytes(b"exe")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        with monkeypatch.context() as m:
            m.setattr(backend, "_runtime_cache_root", lambda: tmp_path / "cache")

            # First call: should build manifest and write disk cache.
            first = backend.runtime_source_manifest_for_test(source_root)
            assert first

            # Simulate new CLI process by clearing in-memory cache.
            runtime_module._MANIFEST_CACHE.clear()  # pyright: ignore[reportPrivateUsage]

            called = False

            def fail_if_called(files: list[tuple[str, Path]]) -> list[_RuntimeManifestEntry]:
                nonlocal called
                called = True
                raise AssertionError(
                    "build_runtime_manifest_entries should not run on disk-cache hit"
                )

            m.setattr(
                runtime_module,
                "build_runtime_manifest_entries",
                fail_if_called,
            )

            second = backend.runtime_source_manifest_for_test(source_root)

            assert not called
            assert second == first

    @pytest.mark.timeout(30)
    def test_runtime_manifest_uses_memory_cache_before_disk(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        source_root = tmp_path / "runtime"
        (source_root / "Lib").mkdir(parents=True)
        (source_root / "Lib" / "a.py").write_text("x = 1", encoding="utf-8")
        (source_root / "python.exe").write_bytes(b"exe")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        with monkeypatch.context() as m:
            m.setattr(backend, "_runtime_cache_root", lambda: tmp_path / "cache")

            first = backend.runtime_source_manifest_for_test(source_root)

            called = False

            def fail_if_called(files: list[tuple[str, Path]]) -> list[_RuntimeManifestEntry]:
                nonlocal called
                called = True
                raise AssertionError("should use memory cache")

            m.setattr(runtime_module, "build_runtime_manifest_entries", fail_if_called)

            second = backend.runtime_source_manifest_for_test(source_root)

            assert not called
            assert second == first

    @pytest.mark.timeout(30)
    def test_runtime_manifest_rebuilds_when_source_file_changes(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        source_root = tmp_path / "runtime"
        (source_root / "Lib").mkdir(parents=True)
        (source_root / "Lib" / "a.py").write_text("x = 1", encoding="utf-8")
        (source_root / "python.exe").write_bytes(b"exe")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        with monkeypatch.context() as m:
            m.setattr(backend, "_runtime_cache_root", lambda: tmp_path / "cache")

            first = backend.runtime_source_manifest_for_test(source_root)
            runtime_module._MANIFEST_CACHE.clear()  # pyright: ignore[reportPrivateUsage]

            changed_file = source_root / "Lib" / "a.py"
            changed_file.write_text("x = 999999", encoding="utf-8")

            called = False
            real_build = build_runtime_manifest_entries

            def wrapped_build(files: list[tuple[str, Path]]) -> list[_RuntimeManifestEntry]:
                nonlocal called
                called = True
                return real_build(files)

            m.setattr(runtime_module, "build_runtime_manifest_entries", wrapped_build)

            second = backend.runtime_source_manifest_for_test(source_root)

            assert called
            assert second != first

    @pytest.mark.timeout(30)
    def test_corrupt_manifest_cache_is_ignored(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        source_root = tmp_path / "runtime"
        (source_root / "Lib").mkdir(parents=True)
        (source_root / "Lib" / "a.py").write_text("x = 1", encoding="utf-8")
        (source_root / "python.exe").write_bytes(b"exe")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        with monkeypatch.context() as m:
            m.setattr(backend, "_runtime_cache_root", lambda: tmp_path / "cache")

            backend.runtime_source_manifest_for_test(source_root)
            runtime_module._MANIFEST_CACHE.clear()  # pyright: ignore[reportPrivateUsage]

            cache_file = _find_manifest_index_file(backend, source_root)
            cache_file.write_text("{ invalid json", encoding="utf-8")

            called = False
            real_build = build_runtime_manifest_entries

            def wrapped_build(files: list[tuple[str, Path]]) -> list[_RuntimeManifestEntry]:
                nonlocal called
                called = True
                return real_build(files)

            m.setattr(runtime_module, "build_runtime_manifest_entries", wrapped_build)

            result = backend.runtime_source_manifest_for_test(source_root)

            assert called
            assert result

    @pytest.mark.timeout(30)
    def test_manifest_cache_schema_mismatch_is_ignored(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        source_root = tmp_path / "runtime"
        (source_root / "Lib").mkdir(parents=True)
        (source_root / "Lib" / "a.py").write_text("x = 1", encoding="utf-8")
        (source_root / "python.exe").write_bytes(b"exe")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        with monkeypatch.context() as m:
            m.setattr(backend, "_runtime_cache_root", lambda: tmp_path / "cache")

            backend.runtime_source_manifest_for_test(source_root)
            runtime_module._MANIFEST_CACHE.clear()  # pyright: ignore[reportPrivateUsage]

            cache_file = _find_manifest_index_file(backend, source_root)
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            data["schema_version"] = 999
            cache_file.write_text(json.dumps(data), encoding="utf-8")

            called = False
            real_build = build_runtime_manifest_entries

            def wrapped_build(files: list[tuple[str, Path]]) -> list[_RuntimeManifestEntry]:
                nonlocal called
                called = True
                return real_build(files)

            m.setattr(runtime_module, "build_runtime_manifest_entries", wrapped_build)

            backend.runtime_source_manifest_for_test(source_root)

            assert called

    @pytest.mark.timeout(30)
    def test_manifest_cache_digest_algorithm_mismatch_is_ignored(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        source_root = tmp_path / "runtime"
        (source_root / "Lib").mkdir(parents=True)
        (source_root / "Lib" / "a.py").write_text("x = 1", encoding="utf-8")
        (source_root / "python.exe").write_bytes(b"exe")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        with monkeypatch.context() as m:
            m.setattr(backend, "_runtime_cache_root", lambda: tmp_path / "cache")

            backend.runtime_source_manifest_for_test(source_root)
            runtime_module._MANIFEST_CACHE.clear()  # pyright: ignore[reportPrivateUsage]

            cache_file = _find_manifest_index_file(backend, source_root)
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            data["digest_algorithm"] = "sha256"
            cache_file.write_text(json.dumps(data), encoding="utf-8")

            called = False
            real_build = build_runtime_manifest_entries

            def wrapped_build(files: list[tuple[str, Path]]) -> list[_RuntimeManifestEntry]:
                nonlocal called
                called = True
                return real_build(files)

            m.setattr(runtime_module, "build_runtime_manifest_entries", wrapped_build)

            backend.runtime_source_manifest_for_test(source_root)

            assert called

    @pytest.mark.timeout(30)
    def test_manifest_cache_missing_entry_fields_is_ignored(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        source_root = tmp_path / "runtime"
        (source_root / "Lib").mkdir(parents=True)
        (source_root / "Lib" / "a.py").write_text("x = 1", encoding="utf-8")
        (source_root / "python.exe").write_bytes(b"exe")

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        with monkeypatch.context() as m:
            m.setattr(backend, "_runtime_cache_root", lambda: tmp_path / "cache")

            backend.runtime_source_manifest_for_test(source_root)
            runtime_module._MANIFEST_CACHE.clear()  # pyright: ignore[reportPrivateUsage]

            cache_file = _find_manifest_index_file(backend, source_root)
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            del data["manifest"][0]["digest"]
            cache_file.write_text(json.dumps(data), encoding="utf-8")

            called = False
            real_build = build_runtime_manifest_entries

            def wrapped_build(files: list[tuple[str, Path]]) -> list[_RuntimeManifestEntry]:
                nonlocal called
                called = True
                return real_build(files)

            m.setattr(runtime_module, "build_runtime_manifest_entries", wrapped_build)

            backend.runtime_source_manifest_for_test(source_root)

            assert called

    @pytest.mark.timeout(30)
    def test_runtime_copy_rejects_paths_outside_source_root(self, tmp_path: Path) -> None:
        source_root = tmp_path / "source"
        source_root.mkdir()
        (source_root / "python.exe").write_bytes(b"exe")
        (source_root / "Lib").mkdir()

        runtime_path = tmp_path / "runtime"
        backend = InspectableWindowsAppContainerBackend(SandboxConfig())

        # Test case 1: Relative traversal
        entry_traversal = _RuntimeManifestEntry(path="../../secret.txt", size=10, digest="abc")
        with pytest.raises(
            SandboxSetupError, match="Refusing to copy runtime file outside source root"
        ):
            backend.copy_runtime_cache_for_test(source_root, runtime_path, [entry_traversal])

        # Test case 2: Absolute path
        entry_absolute = _RuntimeManifestEntry(
            path="C:\\Windows\\System32\\calc.exe" if sys.platform == "win32" else "/bin/sh",
            size=10,
            digest="abc",
        )
        with pytest.raises(
            SandboxSetupError, match="Refusing to copy runtime file outside source root"
        ):
            backend.copy_runtime_cache_for_test(source_root, runtime_path, [entry_absolute])

        # Test case 3: UNC share / absolute
        entry_unc = _RuntimeManifestEntry(
            path="\\\\server\\share\\file.py" if sys.platform == "win32" else "/absolute/file.py",
            size=10,
            digest="abc",
        )
        with pytest.raises(
            SandboxSetupError, match="Refusing to copy runtime file outside source root"
        ):
            backend.copy_runtime_cache_for_test(source_root, runtime_path, [entry_unc])

        # Test case 4: Traversal just above source root
        entry_parent = _RuntimeManifestEntry(path="../outside.py", size=10, digest="abc")
        with pytest.raises(
            SandboxSetupError, match="Refusing to copy runtime file outside source root"
        ):
            backend.copy_runtime_cache_for_test(source_root, runtime_path, [entry_parent])

    @pytest.mark.timeout(30)
    def test_runtime_cache_reuse_skips_full_verification_within_process(
        self,
        tmp_path: Path,
    ) -> None:
        source_root = tmp_path / "source"
        _write_minimal_runtime(source_root, "value = 1\n")
        cache_root = tmp_path / "cache"
        jail_path = tmp_path / "jail"
        jail_path.mkdir()

        runtime_module._MANIFEST_CACHE.clear()  # pyright: ignore[reportPrivateUsage]
        runtime_module._VERIFIED_RUNTIME_CACHE.clear()  # pyright: ignore[reportPrivateUsage]

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        backend.set_jail_path_for_test(jail_path)
        with (
            patch.object(backend, "_python_runtime_source_root", return_value=source_root),
            patch.object(backend, "_runtime_cache_root", return_value=cache_root),
        ):
            backend.stage_python_runtime_for_test()
            built_runtime = backend.runtime_path_for_test()
            assert built_runtime is not None

            with patch.object(
                backend,
                "_verify_runtime_cache",
                wraps=backend._verify_runtime_cache,  # pyright: ignore[reportPrivateUsage]
            ) as verify_spy:
                # First reuse in this process: full content hashing runs once
                # and records the verified stat snapshot.
                backend.stage_python_runtime_for_test()
                assert verify_spy.call_count == 1
                assert backend.runtime_path_for_test() == built_runtime

                # Second reuse: unchanged stat snapshot takes the fast path and
                # does not re-hash the staged tree.
                backend.stage_python_runtime_for_test()
                assert verify_spy.call_count == 1
                assert backend.runtime_path_for_test() == built_runtime

    @pytest.mark.timeout(30)
    def test_runtime_cache_reuse_rehashes_when_stat_snapshot_changes(
        self,
        tmp_path: Path,
    ) -> None:
        source_root = tmp_path / "source"
        _write_minimal_runtime(source_root, "value = 1\n")
        cache_root = tmp_path / "cache"
        jail_path = tmp_path / "jail"
        jail_path.mkdir()

        runtime_module._MANIFEST_CACHE.clear()  # pyright: ignore[reportPrivateUsage]
        runtime_module._VERIFIED_RUNTIME_CACHE.clear()  # pyright: ignore[reportPrivateUsage]

        backend = InspectableWindowsAppContainerBackend(SandboxConfig())
        backend.set_jail_path_for_test(jail_path)
        with (
            patch.object(backend, "_python_runtime_source_root", return_value=source_root),
            patch.object(backend, "_runtime_cache_root", return_value=cache_root),
        ):
            backend.stage_python_runtime_for_test()
            backend.stage_python_runtime_for_test()
            built_runtime = backend.runtime_path_for_test()
            assert built_runtime is not None

            staged_module = built_runtime / "Lib" / "module.py"
            stat = staged_module.stat()
            os.utime(
                staged_module,
                ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000),
            )

            with patch.object(
                backend,
                "_verify_runtime_cache",
                wraps=backend._verify_runtime_cache,  # pyright: ignore[reportPrivateUsage]
            ) as verify_spy:
                # The staged tree content is unchanged, but its stat snapshot
                # drifted, so the fast path is invalidated and full content
                # hashing runs again rather than trusting the memo.
                backend.stage_python_runtime_for_test()
                assert verify_spy.call_count == 1
                assert backend.runtime_path_for_test() == built_runtime
