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

import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import RUNTIME_CACHE_DIRNAME

from .build import WindowsRuntimeBuildMixin
from .cache import (
    RuntimeManifestEntry as _RuntimeManifestEntry,
)
from .cache import (
    build_runtime_manifest_entries,
)
from .manifests import (
    MANIFEST_CACHE,
    runtime_source_manifest,
    runtime_source_snapshot,
)
from .manifests import (
    RuntimeSourceSnapshot as _RuntimeSourceSnapshot,
)
from .validation import (
    VERIFIED_RUNTIME_CACHE,
    collect_runtime_cache_files,
    is_generated_runtime_cache_file,
    iter_runtime_cache_files,
    purge_runtime_cache_files,
    remove_cache_tree,
    runtime_cache_stat_snapshot,
    verify_runtime_cache,
    verify_runtime_cache_reuse,
)

if TYPE_CHECKING:
    from pysymex._internal.config.sandbox.types import SandboxConfig

_MANIFEST_CACHE = MANIFEST_CACHE
_VERIFIED_RUNTIME_CACHE = VERIFIED_RUNTIME_CACHE


class WindowsRuntimeCacheMixin(WindowsRuntimeBuildMixin):
    """Mixin for staging and validating the cached CPython runtime."""

    if TYPE_CHECKING:
        config: SandboxConfig
        _jail_path: Path | None
        _runtime_path: Path | None

        def _grant_runtime_cache_access(self, runtime_path: Path, *, recursive: bool) -> None: ...

    def _stage_python_runtime(self) -> None:
        """Select or build the immutable CPython runtime cache for AppContainer execution."""
        if self._jail_path is None:
            msg = "Windows AppContainer jail is unavailable"
            raise SandboxSetupError(msg)

        source_root = self._python_runtime_source_root()
        source_executable = source_root / "python.exe"
        source_lib = source_root / "Lib"
        if not source_executable.is_file():
            msg = f"Windows AppContainer runtime is missing python.exe: {source_root}"
            raise SandboxSetupError(
                msg,
            )
        if not source_lib.is_dir():
            msg = f"Windows AppContainer runtime is missing standard library: {source_lib}"
            raise SandboxSetupError(
                msg,
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
        return runtime_source_manifest(
            source_root,
            self._runtime_cache_root(),
            build_manifest_entries=build_runtime_manifest_entries,
        )

    @staticmethod
    def _runtime_source_snapshot(
        source_files: list[tuple[str, Path]],
    ) -> _RuntimeSourceSnapshot:
        return runtime_source_snapshot(source_files)

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
        return verify_runtime_cache_reuse(
            runtime_path,
            entries,
            verify_runtime_cache=self._verify_runtime_cache,
            runtime_cache_stat_snapshot=self._runtime_cache_stat_snapshot,
        )

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
        return runtime_cache_stat_snapshot(runtime_path)

    def _verify_runtime_cache(
        self,
        runtime_path: Path,
        entries: list[_RuntimeManifestEntry],
    ) -> bool:
        """Verify cached files and metadata against the expected manifest."""
        return verify_runtime_cache(runtime_path, entries)

    def _iter_runtime_cache_files(self, runtime_path: Path) -> list[tuple[str, Path]]:
        return iter_runtime_cache_files(runtime_path)

    def _collect_runtime_cache_files(
        self,
        directory: Path,
        relative_prefix: str,
        files: list[tuple[str, Path]],
    ) -> None:
        collect_runtime_cache_files(directory, relative_prefix, files)

    def _purge_runtime_cache_files(
        self,
        runtime_path: Path,
        generated_files: list[Path],
    ) -> None:
        """Delete generated runtime files found during cache verification."""
        purge_runtime_cache_files(runtime_path, generated_files)

    @staticmethod
    def _is_generated_runtime_cache_file(relative_path: str) -> bool:
        return is_generated_runtime_cache_file(relative_path)

    @staticmethod
    def _remove_cache_tree(cache_root: Path, target: Path) -> None:
        """Delete a generated directory only when it is inside the cache root."""
        remove_cache_tree(cache_root, target)

    def _python_runtime_source_root(self) -> Path:
        if self.config.python_executable is None:
            return Path(sys.base_prefix).resolve()

        configured = Path(self.config.python_executable).expanduser().resolve()
        source_root = configured.parent
        if not (source_root / "Lib").is_dir():
            msg = (
                "Windows AppContainer python_executable must point to python.exe in a "
                f"complete CPython runtime containing a Lib directory: {configured}"
            )
            raise SandboxSetupError(
                msg,
            )
        return source_root

    def _runtime_python_cmd(self) -> list[str]:
        if self._runtime_path is None:
            msg = "Windows AppContainer Python runtime is not staged"
            raise SandboxSetupError(msg)
        return [str(self._runtime_path / "python.exe"), "-I", "-B", "-S"]
