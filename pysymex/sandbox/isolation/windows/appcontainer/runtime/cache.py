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

import hashlib
import json
import os
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

_PARALLEL_HASH_MIN_FILES = 8
_PARALLEL_HASH_MIN_BYTES = 32 * 1024 * 1024
_MAX_HASH_WORKERS = 8
_RUNTIME_DIGEST_ALGORITHM = "sha512_256"


@dataclass(frozen=True, slots=True)
class RuntimeManifestEntry:
    """Metadata describing a single file in the staged Python runtime."""

    path: str
    size: int
    digest: str

    def to_json(self) -> dict[str, object]:
        """Convert the entry to a JSON-serializable dictionary."""
        return {"path": self.path, "size": self.size, "digest": self.digest}


def build_runtime_manifest_entries(
    files: Iterable[tuple[str, Path]],
) -> list[RuntimeManifestEntry]:
    """Generate manifest entries for runtime source files."""
    sorted_files = sorted(files, key=lambda item: item[0])
    stat_files = [
        (relative_path, path, path.stat().st_size) for relative_path, path in sorted_files
    ]
    total_bytes = sum(size for _, _, size in stat_files)
    if len(stat_files) >= _PARALLEL_HASH_MIN_FILES and total_bytes >= _PARALLEL_HASH_MIN_BYTES:
        worker_count = min(_MAX_HASH_WORKERS, len(stat_files), os.cpu_count() or 1)
        if worker_count > 1:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                return list(executor.map(_runtime_manifest_entry, stat_files))
    return [_runtime_manifest_entry(item) for item in stat_files]


def runtime_manifest_hash(
    entries: Sequence[RuntimeManifestEntry],
    *,
    schema: int,
    policy: str,
) -> str:
    """Compute the SHA-512/256 content digest for a runtime manifest."""
    payload = {
        "schema": schema,
        "policy": policy,
        "files": [entry.to_json() for entry in entries],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.new(_RUNTIME_DIGEST_ALGORITHM, encoded).hexdigest()


def runtime_manifest_payload(
    entries: Sequence[RuntimeManifestEntry],
    *,
    schema: int,
    policy: str,
) -> dict[str, object]:
    """Build the JSON-serializable manifest payload."""
    return {
        "schema": schema,
        "policy": policy,
        "content_hash": runtime_manifest_hash(entries, schema=schema, policy=policy),
        "files": [entry.to_json() for entry in entries],
    }


def runtime_entries_payload(entries: Sequence[RuntimeManifestEntry]) -> list[dict[str, object]]:
    """Convert manifest entries to their JSON-serializable payload."""
    return [entry.to_json() for entry in entries]


def hash_file_runtime_digest(path: Path) -> str:
    """Calculate the SHA-512/256 digest of a single file."""
    with path.open("rb") as file:
        return hashlib.file_digest(file, _RUNTIME_DIGEST_ALGORITHM).hexdigest()


def _runtime_manifest_entry(item: tuple[str, Path, int]) -> RuntimeManifestEntry:
    """Create a manifest entry from a relative path, source path, and size."""
    relative_path, source_path, size = item
    return RuntimeManifestEntry(
        path=relative_path,
        size=size,
        digest=hash_file_runtime_digest(source_path),
    )


__all__ = [
    "RuntimeManifestEntry",
    "build_runtime_manifest_entries",
    "hash_file_runtime_digest",
    "runtime_entries_payload",
    "runtime_manifest_hash",
    "runtime_manifest_payload",
]
