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

"""Runtime cache reuse validation and safe cleanup for Windows AppContainer."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import cast

from pysymex._internal.logging.root import get_logger
from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import (
    RUNTIME_CACHE_POLICY_VERSION,
    RUNTIME_CACHE_SCHEMA,
    RUNTIME_MANIFEST_FILENAME,
)

from .cache import (
    RuntimeManifestEntry,
    build_runtime_manifest_entries,
    runtime_entries_payload,
    runtime_manifest_hash,
)
from .manifests import RuntimeSourceSnapshot, runtime_source_snapshot

logger = get_logger(__name__)

VerifyRuntimeCache = Callable[[Path, list[RuntimeManifestEntry]], bool]
RuntimeCacheSnapshot = Callable[[Path], RuntimeSourceSnapshot | None]

_VERIFIED_RUNTIME_CACHE: dict[Path, RuntimeSourceSnapshot] = {}
VERIFIED_RUNTIME_CACHE = _VERIFIED_RUNTIME_CACHE


def verify_runtime_cache_reuse(
    runtime_path: Path,
    entries: list[RuntimeManifestEntry],
    *,
    verify_runtime_cache: VerifyRuntimeCache,
    runtime_cache_stat_snapshot: RuntimeCacheSnapshot,
) -> bool:
    """Verify a reusable cache, skipping re-hash when this process already proved it."""
    key = runtime_path.resolve()
    verified_snapshot = _VERIFIED_RUNTIME_CACHE.get(key)
    if verified_snapshot is not None:
        current = runtime_cache_stat_snapshot(runtime_path)
        if current is not None and current == verified_snapshot:
            logger.debug("runtime cache: verified-snapshot fast path hit")
            return True
    if not verify_runtime_cache(runtime_path, entries):
        _VERIFIED_RUNTIME_CACHE.pop(key, None)
        return False
    snapshot = runtime_cache_stat_snapshot(runtime_path)
    if snapshot is not None:
        _VERIFIED_RUNTIME_CACHE[key] = snapshot
    else:
        _VERIFIED_RUNTIME_CACHE.pop(key, None)
    return True


def runtime_cache_stat_snapshot(runtime_path: Path) -> RuntimeSourceSnapshot | None:
    """Return a stat snapshot of every staged cache file, or None if unreadable."""
    try:
        cached_files = iter_runtime_cache_files(runtime_path)
        return runtime_source_snapshot(cached_files)
    except OSError:
        return None


def verify_runtime_cache(
    runtime_path: Path,
    entries: list[RuntimeManifestEntry],
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
    if payload.get("content_hash") != runtime_manifest_hash(
        entries,
        schema=RUNTIME_CACHE_SCHEMA,
        policy=RUNTIME_CACHE_POLICY_VERSION,
    ):
        return False
    expected_payload = runtime_entries_payload(entries)
    if payload.get("files") != expected_payload:
        return False

    try:
        cached_files = iter_runtime_cache_files(runtime_path)
        generated_files: list[Path] = []
        manifest_files: list[tuple[str, Path]] = []
        for relative_path, cached_file in cached_files:
            if relative_path == RUNTIME_MANIFEST_FILENAME:
                continue
            if is_generated_runtime_cache_file(relative_path):
                generated_files.append(cached_file)
                continue
            manifest_files.append((relative_path, cached_file))
        cached_entries = build_runtime_manifest_entries(manifest_files)
        purge_runtime_cache_files(runtime_path, generated_files)
    except OSError:
        return False
    return runtime_entries_payload(cached_entries) == expected_payload


def iter_runtime_cache_files(runtime_path: Path) -> list[tuple[str, Path]]:
    """Return non-symlink files in the staged runtime cache tree."""
    files: list[tuple[str, Path]] = []
    collect_runtime_cache_files(runtime_path, "", files)
    return sorted(files, key=lambda item: item[0])


def collect_runtime_cache_files(
    directory: Path,
    relative_prefix: str,
    files: list[tuple[str, Path]],
) -> None:
    """Append non-symlink files below ``directory`` to ``files``."""
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.is_symlink():
                msg = f"Runtime cache contains symlink: {entry.path}"
                raise OSError(msg)
            relative_path = entry.name if not relative_prefix else f"{relative_prefix}/{entry.name}"
            entry_path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                collect_runtime_cache_files(entry_path, relative_path, files)
            elif entry.is_file(follow_symlinks=False):
                files.append((relative_path, entry_path))


def purge_runtime_cache_files(
    runtime_path: Path,
    generated_files: list[Path],
) -> None:
    """Delete generated runtime files found during cache verification."""
    runtime_root = runtime_path.resolve()
    cache_dirs: set[Path] = set()
    for cached_file in generated_files:
        cached_resolved = cached_file.resolve()
        if runtime_root != cached_resolved and runtime_root not in cached_resolved.parents:
            msg = f"Generated runtime cache file escaped root: {cached_file}"
            raise OSError(msg)
        cached_file.unlink()
        for parent in cached_file.parents:
            if parent == runtime_path:
                break
            if parent.name == "__pycache__":
                cache_dirs.add(parent)

    for cache_dir in sorted(cache_dirs, key=lambda path: len(path.parts), reverse=True):
        cache_resolved = cache_dir.resolve()
        if runtime_root != cache_resolved and runtime_root not in cache_resolved.parents:
            msg = f"Generated runtime cache directory escaped root: {cache_dir}"
            raise OSError(msg)
        with contextlib.suppress(OSError):
            cache_dir.rmdir()


def is_generated_runtime_cache_file(relative_path: str) -> bool:
    """Return whether a cache-relative path is generated Python bytecode."""
    parts = Path(relative_path).parts
    return "__pycache__" in parts and relative_path.lower().endswith((".pyc", ".pyo"))


def remove_cache_tree(cache_root: Path, target: Path) -> None:
    """Delete a generated directory only when it is inside the cache root."""
    cache_root_resolved = cache_root.resolve()
    target_resolved = target.resolve()
    if target_resolved == cache_root_resolved or cache_root_resolved not in target_resolved.parents:
        msg = f"Refusing to remove path outside runtime cache root: {target}"
        raise SandboxSetupError(msg)
    shutil.rmtree(target)
