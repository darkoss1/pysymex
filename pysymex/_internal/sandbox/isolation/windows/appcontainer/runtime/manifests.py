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

"""Source-runtime manifest caching for Windows AppContainer runtime staging."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path

from pysymex._internal.logging.root import get_logger

from .cache import RuntimeManifestEntry, build_runtime_manifest_entries
from .source import iter_runtime_source_files

logger = get_logger(__name__)

RuntimeSourceSnapshot = tuple[tuple[str, int, int, int, int, int, int], ...]
ManifestBuilder = Callable[[list[tuple[str, Path]]], list[RuntimeManifestEntry]]

_RuntimeManifestCacheEntry = tuple[RuntimeSourceSnapshot, tuple[RuntimeManifestEntry, ...]]
_MANIFEST_CACHE: dict[Path, _RuntimeManifestCacheEntry] = {}
MANIFEST_CACHE = _MANIFEST_CACHE


def runtime_source_manifest(
    source_root: Path,
    cache_root: Path,
    *,
    build_manifest_entries: ManifestBuilder = build_runtime_manifest_entries,
) -> list[RuntimeManifestEntry]:
    """Return source runtime manifest entries with memory and disk cache reuse."""
    source_files = list(iter_runtime_source_files(source_root))
    snapshot = runtime_source_snapshot(source_files)
    cache_key = source_root.resolve()

    cached = _MANIFEST_CACHE.get(cache_key)
    if cached is not None and cached[0] == snapshot:
        logger.debug("runtime manifest: memory cache hit")
        return list(cached[1])

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
                        RuntimeManifestEntry(path=f["path"], size=f["size"], digest=f["digest"])
                        for f in data.get("manifest", [])
                    ]
                    _MANIFEST_CACHE[cache_key] = (snapshot, tuple(entries))
                    return entries
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass

    logger.debug("runtime manifest: rebuilding")
    manifest = build_manifest_entries(source_files)

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


def runtime_source_snapshot(
    source_files: list[tuple[str, Path]],
) -> RuntimeSourceSnapshot:
    """Return stat metadata used to detect source or cache tree drift."""
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
