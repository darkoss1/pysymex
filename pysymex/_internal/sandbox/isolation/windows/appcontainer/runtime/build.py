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

"""Runtime cache build and manifest-write helpers for Windows AppContainer."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import (
    RUNTIME_CACHE_POLICY_VERSION,
    RUNTIME_CACHE_SCHEMA,
    RUNTIME_MANIFEST_FILENAME,
)

from .cache import (
    RuntimeManifestEntry as _RuntimeManifestEntry,
)
from .cache import (
    runtime_manifest_hash,
    runtime_manifest_payload,
)

if TYPE_CHECKING:
    from pysymex._internal.config.sandbox.types import SandboxConfig


class WindowsRuntimeBuildMixin:
    """Mixin for populating and atomically publishing AppContainer runtime caches."""

    if TYPE_CHECKING:
        config: SandboxConfig

        def _grant_runtime_cache_access(self, runtime_path: Path, *, recursive: bool) -> None: ...

        def _runtime_cache_root(self) -> Path: ...

        def _verify_runtime_cache_reuse(
            self,
            runtime_path: Path,
            entries: list[_RuntimeManifestEntry],
        ) -> bool: ...

        def _verify_runtime_cache(
            self,
            runtime_path: Path,
            entries: list[_RuntimeManifestEntry],
        ) -> bool: ...

        @staticmethod
        def _remove_cache_tree(cache_root: Path, target: Path) -> None: ...

    def _ensure_runtime_cache(
        self,
        source_root: Path,
        entries: list[_RuntimeManifestEntry],
    ) -> tuple[Path, bool]:
        """Find or populate a cached runtime matching the source manifest."""
        if not entries:
            msg = "Windows AppContainer runtime manifest is empty"
            raise SandboxSetupError(msg)

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
                msg = "New Windows AppContainer runtime cache failed verification"
                raise SandboxSetupError(
                    msg,
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
                msg = f"Refusing to copy runtime file outside source root: {entry.path}"
                raise SandboxSetupError(
                    msg,
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
