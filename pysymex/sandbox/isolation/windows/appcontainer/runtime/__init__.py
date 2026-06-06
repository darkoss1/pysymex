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

"""Runtime cache staging and verification for AppContainer isolation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, cast

from pysymex.logger import get_logger
from .....errors import SandboxSetupError

logger = get_logger(__name__)
from ..shared import (
    RUNTIME_CACHE_DIRNAME,
    RUNTIME_CACHE_POLICY_VERSION,
    RUNTIME_CACHE_SCHEMA,
    RUNTIME_MANIFEST_FILENAME,
)
from .cache import (
    RuntimeManifestEntry as _RuntimeManifestEntry,
    build_runtime_manifest_entries,
    runtime_entries_payload,
    runtime_manifest_hash,
    runtime_manifest_payload,
)
from .source import iter_runtime_source_files

if TYPE_CHECKING:
    from .....types import SandboxConfig


_RuntimeSourceSnapshot = tuple[tuple[str, int, int, int, int, int, int], ...]
_RuntimeManifestCacheEntry = tuple[_RuntimeSourceSnapshot, tuple[_RuntimeManifestEntry, ...]]
_MANIFEST_CACHE: dict[Path, _RuntimeManifestCacheEntry] = {}

# Process-local record of staged runtime caches whose full content hashes were
# already verified in this process, keyed by resolved runtime path and storing
# the stat snapshot observed at verification time. The staged runtime is
# immutable to the sandboxed AppContainer (deny-write ACLs that the live setup
# self-check re-proves on every setup), so re-hashing every byte on each warm
# reuse is redundant once a process has verified the tree. Any change to the
# cheap stat snapshot invalidates the memo and forces full re-hashing.
_VERIFIED_RUNTIME_CACHE: dict[Path, _RuntimeSourceSnapshot] = {}


class WindowsRuntimeCacheMixin:
    """Mixin for staging and validating the cached CPython runtime."""

    if TYPE_CHECKING:
        config: SandboxConfig
        _jail_path: Path | None
        _runtime_path: Path | None

        def _grant_runtime_cache_access(self, runtime_path: Path, *, recursive: bool) -> None: ...

    def _stage_python_runtime(self) -> None:
        """Select or build the immutable CPython runtime cache for AppContainer execution."""
        if self._jail_path is None:
            raise SandboxSetupError("Windows AppContainer jail is unavailable")

        source_root = self._python_runtime_source_root()
        source_executable = source_root / "python.exe"
        source_lib = source_root / "Lib"
        if not source_executable.is_file():
            raise SandboxSetupError(
                f"Windows AppContainer runtime is missing python.exe: {source_root}"
            )
        if not source_lib.is_dir():
            raise SandboxSetupError(
                f"Windows AppContainer runtime is missing standard library: {source_lib}"
            )

        entries = self._runtime_source_manifest(source_root)
        self._runtime_path, newly_built = self._ensure_runtime_cache(source_root, entries)
        if sys.platform == "win32" and newly_built:
            self._grant_runtime_cache_access(self._runtime_path, recursive=True)

    def _runtime_cache_root(self) -> Path:
        base = (
            Path(self.config.working_directory)
            if self.config.working_directory
            else Path(tempfile.gettempdir())
        )
        return base / "pysymex" / RUNTIME_CACHE_DIRNAME

    def _runtime_source_manifest(self, source_root: Path) -> list[_RuntimeManifestEntry]:
        # Ensure we evaluate to a list/tuple so that we don't exhaust generators
        source_files = list(iter_runtime_source_files(source_root))
        snapshot = self._runtime_source_snapshot(source_files)
        cache_key = source_root.resolve()

        cached = _MANIFEST_CACHE.get(cache_key)
        if cached is not None and cached[0] == snapshot:
            logger.debug("runtime manifest: memory cache hit")
            return list(cached[1])

        cache_root = self._runtime_cache_root()
        safe_key = hashlib.new("sha512_256", str(cache_key).encode("utf-8")).hexdigest()[:32]
        disk_cache_file = cache_root / f"manifest_index_{safe_key}.json"

        if disk_cache_file.is_file():
            try:
                data = json.loads(disk_cache_file.read_text(encoding="utf-8"))
                if (
                    data.get("schema_version") == 1
                    and data.get("digest_algorithm") == "sha512_256"
                    and data.get("source_root") == str(cache_key)
                ):
                    disk_snapshot = tuple(tuple(item) for item in data.get("snapshot", []))
                    if disk_snapshot == snapshot:
                        logger.debug("runtime manifest: disk cache hit")
                        entries = [
                            _RuntimeManifestEntry(
                                path=f["path"], size=f["size"], digest=f["digest"]
                            )
                            for f in data.get("manifest", [])
                        ]
                        _MANIFEST_CACHE[cache_key] = (snapshot, tuple(entries))
                        return entries
            except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                pass

        logger.debug("runtime manifest: rebuilding")
        manifest = build_runtime_manifest_entries(source_files)

        try:
            logger.debug("runtime manifest: writing disk cache")
            cache_root.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema_version": 1,
                "digest_algorithm": "sha512_256",
                "source_root": str(cache_key),
                "snapshot": snapshot,
                "manifest": [entry.to_json() for entry in manifest],
            }
            temp_disk_cache = disk_cache_file.with_name(f"{disk_cache_file.name}.{os.getpid()}.tmp")
            temp_disk_cache.write_text(json.dumps(payload), encoding="utf-8")
            temp_disk_cache.replace(disk_cache_file)
        except (OSError, TypeError, ValueError):
            pass

        _MANIFEST_CACHE[cache_key] = (snapshot, tuple(manifest))
        return manifest

    @staticmethod
    def _runtime_source_snapshot(
        source_files: list[tuple[str, Path]],
    ) -> _RuntimeSourceSnapshot:
        return tuple(
            (
                relative_path,
                stat.st_size,
                stat.st_mtime_ns,
                stat.st_ctime_ns,
                stat.st_ino,
                stat.st_dev,
                stat.st_mode,
            )
            for relative_path, source_path in source_files
            for stat in (source_path.stat(),)
        )

    def _ensure_runtime_cache(
        self,
        source_root: Path,
        entries: list[_RuntimeManifestEntry],
    ) -> tuple[Path, bool]:
        """Find or populate a cached runtime matching the source manifest."""
        if not entries:
            raise SandboxSetupError("Windows AppContainer runtime manifest is empty")

        manifest_hash = self._runtime_manifest_hash(entries)
        cache_root = self._runtime_cache_root()
        cache_root.mkdir(parents=True, exist_ok=True)
        runtime_path = cache_root / f"{RUNTIME_CACHE_POLICY_VERSION}-{manifest_hash[:32]}"
        if runtime_path.exists():
            if self._verify_runtime_cache_reuse(runtime_path, entries):
                return runtime_path, False
            self._remove_cache_tree(cache_root, runtime_path)

        temp_path = cache_root / f".{runtime_path.name}.{os.getpid()}.{time.time_ns()}.tmp"
        if temp_path.exists():
            self._remove_cache_tree(cache_root, temp_path)
        temp_path.mkdir(parents=False, exist_ok=False)
        try:
            if sys.platform == "win32":
                self._grant_runtime_cache_access(temp_path, recursive=False)
            self._copy_runtime_cache(source_root, temp_path, entries)
            self._write_runtime_manifest(temp_path, entries)
            if not self._verify_runtime_cache(temp_path, entries):
                raise SandboxSetupError(
                    "New Windows AppContainer runtime cache failed verification"
                )
            try:
                self._rename_runtime_cache(temp_path, runtime_path)
            except FileExistsError:
                if self._verify_runtime_cache(runtime_path, entries):
                    self._remove_cache_tree(cache_root, temp_path)
                    return runtime_path, False
                raise
            return runtime_path, True
        except Exception:
            if temp_path.exists():
                self._remove_cache_tree(cache_root, temp_path)
            raise

    @staticmethod
    def _rename_runtime_cache(temp_path: Path, runtime_path: Path) -> None:
        attempts = 8 if sys.platform == "win32" else 1
        for attempt in range(attempts):
            try:
                temp_path.rename(runtime_path)
                return
            except PermissionError:
                if attempt == attempts - 1:
                    raise
                time.sleep(min(0.05 * (attempt + 1), 0.25))

    @staticmethod
    def _runtime_manifest_hash(entries: list[_RuntimeManifestEntry]) -> str:
        return runtime_manifest_hash(
            entries,
            schema=RUNTIME_CACHE_SCHEMA,
            policy=RUNTIME_CACHE_POLICY_VERSION,
        )

    def _copy_runtime_cache(
        self,
        source_root: Path,
        runtime_path: Path,
        entries: list[_RuntimeManifestEntry],
    ) -> None:
        source_root_resolved = source_root.resolve()
        for entry in entries:
            source = (source_root / Path(entry.path)).resolve()
            if source != source_root_resolved and source_root_resolved not in source.parents:
                raise SandboxSetupError(
                    f"Refusing to copy runtime file outside source root: {entry.path}"
                )
            target = runtime_path / Path(entry.path)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def _write_runtime_manifest(
        self,
        runtime_path: Path,
        entries: list[_RuntimeManifestEntry],
    ) -> None:
        payload = runtime_manifest_payload(
            entries,
            schema=RUNTIME_CACHE_SCHEMA,
            policy=RUNTIME_CACHE_POLICY_VERSION,
        )
        (runtime_path / RUNTIME_MANIFEST_FILENAME).write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    def _verify_runtime_cache_reuse(
        self,
        runtime_path: Path,
        entries: list[_RuntimeManifestEntry],
    ) -> bool:
        """Verify a reusable cache, skipping re-hash when this process proved it.

        Cold build and the first reuse per process run the full content-hash
        verification in `_verify_runtime_cache`. Because the staged runtime is
        immutable to the AppContainer (deny-write ACLs re-proven every setup by
        the live self-check), subsequent reuse within the same process only
        re-validates a cheap stat snapshot. A snapshot mismatch, an unreadable
        tree, or a symlink falls back to full content hashing.
        """
        key = runtime_path.resolve()
        verified_snapshot = _VERIFIED_RUNTIME_CACHE.get(key)
        if verified_snapshot is not None:
            current = self._runtime_cache_stat_snapshot(runtime_path)
            if current is not None and current == verified_snapshot:
                logger.debug("runtime cache: verified-snapshot fast path hit")
                return True
        if not self._verify_runtime_cache(runtime_path, entries):
            _VERIFIED_RUNTIME_CACHE.pop(key, None)
            return False
        snapshot = self._runtime_cache_stat_snapshot(runtime_path)
        if snapshot is not None:
            _VERIFIED_RUNTIME_CACHE[key] = snapshot
        else:
            _VERIFIED_RUNTIME_CACHE.pop(key, None)
        return True

    def _runtime_cache_stat_snapshot(
        self,
        runtime_path: Path,
    ) -> _RuntimeSourceSnapshot | None:
        """Return a stat snapshot of every staged cache file, or None if unreadable.

        The snapshot mirrors the source-side trust model: it records identity
        and size metadata for every file (computed after generated-bytecode
        cleanup), so an unchanged tree is recognized without re-hashing.
        Returns ``None`` when the tree contains a symlink or any file cannot be
        stat'd, which forces full content verification.
        """
        try:
            cached_files = self._iter_runtime_cache_files(runtime_path)
            return self._runtime_source_snapshot(cached_files)
        except OSError:
            return None

    def _verify_runtime_cache(
        self,
        runtime_path: Path,
        entries: list[_RuntimeManifestEntry],
    ) -> bool:
        """Verify cached files and metadata against the expected manifest."""
        manifest_path = runtime_path / RUNTIME_MANIFEST_FILENAME
        if not manifest_path.is_file() or manifest_path.is_symlink():
            return False
        try:
            payload_obj: object = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        if not isinstance(payload_obj, dict):
            return False
        payload = cast("dict[str, object]", payload_obj)
        if payload.get("schema") != RUNTIME_CACHE_SCHEMA:
            return False
        if payload.get("policy") != RUNTIME_CACHE_POLICY_VERSION:
            return False
        if payload.get("content_hash") != self._runtime_manifest_hash(entries):
            return False
        expected_payload = runtime_entries_payload(entries)
        if payload.get("files") != expected_payload:
            return False

        try:
            cached_files = self._iter_runtime_cache_files(runtime_path)
            generated_files: list[Path] = []
            manifest_files: list[tuple[str, Path]] = []
            for relative_path, cached_file in cached_files:
                if relative_path == RUNTIME_MANIFEST_FILENAME:
                    continue
                if self._is_generated_runtime_cache_file(relative_path):
                    generated_files.append(cached_file)
                    continue
                manifest_files.append((relative_path, cached_file))
            cached_entries = build_runtime_manifest_entries(manifest_files)
            self._remove_runtime_cache_generated_files(runtime_path, generated_files)
        except OSError:
            return False
        return runtime_entries_payload(cached_entries) == expected_payload

    def _iter_runtime_cache_files(self, runtime_path: Path) -> list[tuple[str, Path]]:
        files: list[tuple[str, Path]] = []
        self._collect_runtime_cache_files(runtime_path, "", files)
        return sorted(files, key=lambda item: item[0])

    def _collect_runtime_cache_files(
        self,
        directory: Path,
        relative_prefix: str,
        files: list[tuple[str, Path]],
    ) -> None:
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_symlink():
                    raise OSError(f"Runtime cache contains symlink: {entry.path}")
                relative_path = (
                    entry.name if not relative_prefix else f"{relative_prefix}/{entry.name}"
                )
                entry_path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    self._collect_runtime_cache_files(entry_path, relative_path, files)
                elif entry.is_file(follow_symlinks=False):
                    files.append((relative_path, entry_path))

    def _remove_runtime_cache_generated_files(
        self,
        runtime_path: Path,
        generated_files: list[Path],
    ) -> None:
        """Delete generated runtime files found during cache verification."""
        runtime_root = runtime_path.resolve()
        cache_dirs: set[Path] = set()
        for cached_file in generated_files:
            cached_resolved = cached_file.resolve()
            if runtime_root != cached_resolved and runtime_root not in cached_resolved.parents:
                raise OSError(f"Generated runtime cache file escaped root: {cached_file}")
            cached_file.unlink()
            for parent in cached_file.parents:
                if parent == runtime_path:
                    break
                if parent.name == "__pycache__":
                    cache_dirs.add(parent)

        for cache_dir in sorted(cache_dirs, key=lambda path: len(path.parts), reverse=True):
            cache_resolved = cache_dir.resolve()
            if runtime_root != cache_resolved and runtime_root not in cache_resolved.parents:
                raise OSError(f"Generated runtime cache directory escaped root: {cache_dir}")
            try:
                cache_dir.rmdir()
            except OSError:
                pass

    @staticmethod
    def _is_generated_runtime_cache_file(relative_path: str) -> bool:
        parts = Path(relative_path).parts
        return "__pycache__" in parts and relative_path.lower().endswith((".pyc", ".pyo"))

    @staticmethod
    def _remove_cache_tree(cache_root: Path, target: Path) -> None:
        """Delete a generated directory only when it is inside the cache root."""
        cache_root_resolved = cache_root.resolve()
        target_resolved = target.resolve()
        if (
            target_resolved == cache_root_resolved
            or cache_root_resolved not in target_resolved.parents
        ):
            raise SandboxSetupError(f"Refusing to remove path outside runtime cache root: {target}")
        shutil.rmtree(target)

    def _python_runtime_source_root(self) -> Path:
        if self.config.python_executable is None:
            return Path(sys.base_prefix).resolve()

        configured = Path(self.config.python_executable).expanduser().resolve()
        source_root = configured.parent
        if not (source_root / "Lib").is_dir():
            raise SandboxSetupError(
                "Windows AppContainer python_executable must point to python.exe in a "
                f"complete CPython runtime containing a Lib directory: {configured}"
            )
        return source_root

    def _runtime_python_cmd(self) -> list[str]:
        if self._runtime_path is None:
            raise SandboxSetupError("Windows AppContainer Python runtime is not staged")
        return [str(self._runtime_path / "python.exe"), "-I", "-B", "-S"]
