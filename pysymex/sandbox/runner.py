# pysymex: Python Symbolic Execution & Formal Verification
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

"""Main sandbox runner interface.

This module provides the primary SandboxRunner class that users
interact with to execute untrusted code safely.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .errors import (
    SandboxError,
    SandboxSetupError,
)
from .types import (
    ResourceLimits,
    SandboxBackend,
    SandboxConfig,
    SandboxResult,
    SecurityCapabilities,
)

if TYPE_CHECKING:
    from .isolation import IsolationBackend


_SUSPICIOUS_RE: re.Pattern[str] = re.compile(
    r"__subclasses__|__globals__|__bases__|__mro__|__builtins__|"
    r"__loader__|__spec__|__import__|_io\.FileIO|"
    r"os\.system|os\.popen|os\.exec|os\.spawn|codecs\.open"
)


_SAFE_FILENAME_CHARS: frozenset[str] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
)

_STRICT_DEFAULT_REQUIRED_CAPABILITIES: SecurityCapabilities = SecurityCapabilities(
    process_isolation=True,
    filesystem_jail=True,
    memory_limits=True,
    cpu_limits=True,
    process_limits=True,
)


def _sanitize_extra_files(
    extra_files: dict[str, bytes] | None,
) -> dict[str, bytes]:
    """Validate and normalize extra file paths copied into the jail.

    The mapping keys must be jail-relative POSIX-like paths without
    traversal, drive prefixes, or absolute roots.
    """
    if not extra_files:
        return {}

    sanitized: dict[str, bytes] = {}
    for rel_path, content in extra_files.items():
        path_text = str(rel_path).replace("\\", "/")
        if not path_text or path_text.startswith("/"):
            raise ValueError(f"extra_files path must be relative: {rel_path!r}")
        if ":" in path_text:
            raise ValueError(f"extra_files path must not include drive prefix: {rel_path!r}")

        parts = [p for p in path_text.split("/") if p not in {"", "."}]
        if not parts:
            raise ValueError(f"extra_files path resolves to empty path: {rel_path!r}")
        if any(part == ".." for part in parts):
            raise ValueError(f"extra_files path traversal is not allowed: {rel_path!r}")
        if any(part.startswith("-") for part in parts):
            raise ValueError(f"extra_files path segment starts with '-': {rel_path!r}")

        normalized = "/".join(parts)
        sanitized[normalized] = bytes(content)

    return sanitized


def _missing_capabilities(
    required: SecurityCapabilities,
    actual: SecurityCapabilities,
) -> list[str]:
    """Return names of required capabilities that are not enforced."""
    missing: list[str] = []
    for name in SecurityCapabilities.__dataclass_fields__:
        if getattr(required, name) and not getattr(actual, name):
            missing.append(name)
    return missing


def _enforce_extra_file_limits(
    extra_files: dict[str, bytes],
    limits: ResourceLimits,
) -> None:
    """Enforce conservative limits for supplementary files copied to jail."""
    max_files = 256
    if len(extra_files) > max_files:
        raise ValueError(f"Too many extra files: {len(extra_files)} (max {max_files})")

    per_file_limit = limits.max_file_size_mb * 1024 * 1024
    total_limit = per_file_limit * 4
    total_bytes = 0
    for path, content in extra_files.items():
        size = len(content)
        if size > per_file_limit:
            raise ValueError(
                f"extra_files entry too large for {path!r}: {size} bytes (max {per_file_limit})"
            )
        total_bytes += size
        if total_bytes > total_limit:
            raise ValueError(
                f"Combined extra_files payload too large: {total_bytes} bytes (max {total_limit})"
            )


def _validate_sandbox_filename(name: str) -> None:
    """Validate a filename that will be used inside the sandbox jail.

    Raises:
        ValueError: If the filename contains dangerous characters.
    """
    if not name:
        msg = "Empty filename"
        raise ValueError(msg)
    if "/" in name or "\\" in name or ".." in name:
        msg = f"Filename contains path separators or traversal: {name!r}"
        raise ValueError(msg)
    if name.startswith(".") or name.startswith("-"):
        msg = f"Filename starts with dangerous character: {name!r}"
        raise ValueError(msg)
    if not all(ch in _SAFE_FILENAME_CHARS for ch in name):
        msg = f"Filename contains illegal characters: {name!r}"
        raise ValueError(msg)


def _pre_screen_code(code: bytes) -> list[str]:
    """Perform a fast heuristic scan for known attack patterns.

    This is **not** a security boundary â€” it's defence-in-depth.
    OS-level isolation is the real boundary.

    Returns:
        List of suspicious patterns found (empty if clean).
    """
    try:
        text = code.decode("utf-8", errors="replace")
    except Exception:
        return []
    return _SUSPICIOUS_RE.findall(text)


class SandboxRunner:
    """Main interface for executing untrusted code in a secure sandbox.

    The SandboxRunner provides a context manager interface for safe
    code execution.  It automatically selects the best available
    isolation backend for the current platform and handles all
    setup and cleanup.

    Usage::

        config = SandboxConfig()
        with SecureSandbox(config) as sandbox:
            result = sandbox.execute("malicious_script.py")
            print(f"Exit code: {result.exit_code}")
            print(f"Output: {result.get_stdout_text()}")

    The sandbox provides multiple layers of protection:
        1. Process isolation (separate process, not exec())
        2. Filesystem jail (ephemeral temp directory)
        3. Network blocking (namespaces / Job Objects)
        4. Resource limits (CPU, memory, processes)
        5. Syscall filtering (seccomp-bpf where supported)
        6. Hardened harness (MetaPathFinder + restricted builtins)
        7. AST pre-screening for known attack patterns

    Attributes:
        config: The sandbox configuration
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialize the sandbox runner.

        Args:
            config: Sandbox configuration. If None, uses secure defaults.
        """
        self.config: SandboxConfig = config or SandboxConfig()
        self._backend: IsolationBackend | None = None
        self._active: bool = False

    def __enter__(self) -> SandboxRunner:
        """Enter the sandbox context and initialize isolation."""
        self._setup()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit the sandbox context and clean up all resources."""
        self._cleanup()

    @property
    def is_active(self) -> bool:
        """Check if the sandbox is currently active."""
        return self._active

    @property
    def backend_name(self) -> str:
        """Get the name of the active backend."""
        if self._backend is not None:
            return self._backend.name
        return "none"

    def get_capabilities(self) -> SecurityCapabilities:
        """Return the enforced security capabilities of the active backend."""
        if self._backend is not None:
            return self._backend.get_capabilities()
        return SecurityCapabilities()

    def _setup(self) -> None:
        """Initialize the sandbox backend."""
        backend_type = self.config.backend or self._detect_best_backend()
        if not self.config.allow_weak_backends and backend_type in {
            SandboxBackend.SUBPROCESS,
            SandboxBackend.WASM,
        }:
            raise SandboxSetupError(
                "Refusing weak sandbox backend in fail-closed mode. "
                "Set allow_weak_backends=True only for trusted compatibility use."
            )
        self._backend = self._create_backend(backend_type)
        self._backend.setup()

        required = self.config.required_capabilities
        if required is None and not self.config.allow_weak_backends:
            required = _STRICT_DEFAULT_REQUIRED_CAPABILITIES
        if required is not None:
            actual = self._backend.get_capabilities()
            missing = _missing_capabilities(required, actual)
            if missing:
                self._backend.cleanup()
                self._backend = None
                raise SandboxSetupError(
                    "Sandbox backend does not satisfy required capability contract: "
                    + ", ".join(missing)
                )

        self._active = True

    def _cleanup(self) -> None:
        """Clean up sandbox resources."""
        if self._backend is not None:
            try:
                self._backend.cleanup()
            except Exception:
                pass
        self._backend = None
        self._active = False

    @staticmethod
    def _detect_best_backend() -> SandboxBackend:
        """Auto-detect the most secure available backend."""
        if sys.platform == "linux":
            if _check_linux_namespace_support():
                return SandboxBackend.LINUX_NAMESPACE

        elif sys.platform == "win32":
            if _check_windows_job_support():
                return SandboxBackend.WINDOWS_JOB

        elif sys.platform == "darwin":
            import logging

            logging.getLogger(__name__).warning(
                "warning, pysymex sandbox is not yet supported on MacOS"
            )

        if _check_wasm_support():
            return SandboxBackend.WASM

        return SandboxBackend.SUBPROCESS

    def _create_backend(self, backend_type: SandboxBackend) -> IsolationBackend:
        """Create the appropriate isolation backend."""
        if backend_type == SandboxBackend.LINUX_NAMESPACE:
            from .isolation.linux import LinuxNamespaceBackend

            return LinuxNamespaceBackend(self.config)

        if backend_type == SandboxBackend.WINDOWS_JOB:
            from .isolation.windows import WindowsJobBackend

            return WindowsJobBackend(self.config)

        if backend_type == SandboxBackend.WASM:
            from .isolation.wasm import WasmBackend

            return WasmBackend(self.config)

        if backend_type == SandboxBackend.SUBPROCESS:
            from .isolation.subprocess import SubprocessBackend

            return SubprocessBackend(self.config)

        raise SandboxSetupError(f"Unknown backend type: {backend_type}")

    def execute(
        self,
        file_path: str | Path,
        *,
        input_data: bytes | None = None,
        extra_files: dict[str, bytes] | None = None,
    ) -> SandboxResult:
        """Execute a Python file in the sandbox.

        The file is copied into the sandbox jail and executed with
        full isolation.  The original file is never modified.

        Args:
            file_path: Path to the Python file to execute
            input_data: Data to provide on stdin
            extra_files: Additional files to copy into the sandbox

        Returns:
            SandboxResult containing execution status, outputs, metrics

        Raises:
            SandboxError: If sandbox is not active
            FileNotFoundError: If file_path does not exist
        """
        if not self._active or self._backend is None:
            raise SandboxError("Sandbox is not active. Use 'with SecureSandbox() as sb:' syntax.")

        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        code = file_path.read_bytes()
        target_name = file_path.name

        _validate_sandbox_filename(target_name)

        suspicious = _pre_screen_code(code)
        if suspicious:
            return SandboxResult(
                status=cast("SandboxStatus", _import_status().SECURITY_VIOLATION),  # type: ignore[reportUnknownMemberType, reportUnknownArgumentType]  # SECURITY_VIOLATION exists in enum
                error_message=(
                    f"Code rejected by pre-screening: suspicious patterns {suspicious!r}"
                ),
                blocked_operations=[f"pre-screen:{p}" for p in suspicious],
            )

        sanitized_files = _sanitize_extra_files(extra_files)
        _enforce_extra_file_limits(sanitized_files, self.config.limits)

        return self._backend.execute(
            code=code,
            filename=target_name,
            input_data=input_data or b"",
            extra_files=sanitized_files,
        )

    def execute_code(
        self,
        code: str | bytes,
        *,
        filename: str = "sandbox_code.py",
        input_data: bytes | None = None,
        extra_files: dict[str, bytes] | None = None,
    ) -> SandboxResult:
        """Execute Python code directly in the sandbox.

        Args:
            code: Python source code to execute
            filename: Virtual filename for the code
            input_data: Data to provide on stdin
            extra_files: Additional files to copy into sandbox

        Returns:
            SandboxResult containing execution status, outputs, metrics

        Raises:
            SandboxError: If sandbox is not active
        """
        if not self._active or self._backend is None:
            raise SandboxError("Sandbox is not active. Use 'with SecureSandbox() as sb:' syntax.")

        _validate_sandbox_filename(filename)

        if isinstance(code, str):
            code_bytes = code.encode("utf-8")
        else:
            code_bytes = code

        sanitized_files = _sanitize_extra_files(extra_files)
        _enforce_extra_file_limits(sanitized_files, self.config.limits)

        return self._backend.execute(
            code=code_bytes,
            filename=filename,
            input_data=input_data or b"",
            extra_files=sanitized_files,
        )


def _import_status() -> type:
    """Lazy import to avoid circular references."""
    from .types import ExecutionStatus

    return ExecutionStatus


SecureSandbox = SandboxRunner


def _check_linux_namespace_support() -> bool:
    """Check if unprivileged user namespaces are available."""
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone") as fh:
            return fh.read().strip() == "1"
    except FileNotFoundError:
        return True
    except Exception:
        return False


def _check_windows_job_support() -> bool:
    """Check if Windows Job Objects are available."""
    if sys.platform != "win32":
        return False
    try:
        import platform

        version = platform.version()
        major = int(version.split(".")[0])
        return major >= 10
    except Exception:
        return False


def _check_wasm_support() -> bool:
    """Check if wasmtime is available."""
    try:
        import wasmtime  # type: ignore[reportUnusedImport]  # Import to check availability

        return True
    except ImportError:
        return False


__all__ = [
    "SandboxRunner",
    "SecureSandbox",
]
