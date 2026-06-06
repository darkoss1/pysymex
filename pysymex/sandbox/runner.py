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

"""Main sandbox runner interface.

This module provides the primary SandboxRunner class that users
interact with to execute untrusted code safely.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from pysymex.logger import get_logger

from .backend_selection import (
    check_linux_namespace_support,
    check_wasm_support,
    check_windows_appcontainer_support,
    disable_windows_appcontainer_auto,
    missing_capabilities,
    strength_from_capabilities,
    strict_default_required_capabilities,
)
from .errors import (
    SandboxError,
    SandboxSetupError,
)
from .path_policy import sanitize_extra_files, validate_sandbox_filename
from .types import (
    ResourceLimits,
    SandboxBackend,
    SandboxBackendStrength,
    SandboxConfig,
    SandboxResult,
    SecurityCapabilities,
)

if TYPE_CHECKING:
    from .isolation import IsolationBackend

logger = get_logger(__name__)


class _WorkspaceResetBackend(Protocol):
    def reset_workspace(self) -> None: ...


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
        3. Network blocking when a strong backend provides it
        4. Resource limits (CPU, memory, processes)
        5. Syscall filtering (seccomp-bpf where supported)

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
        self._backend_type: SandboxBackend | None = None
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

    @property
    def backend_strength(self) -> SandboxBackendStrength:
        """Return the active backend strength without overstating partial setup."""
        if self._backend is None or self._backend_type is None:
            return SandboxBackendStrength.UNAVAILABLE
        return strength_from_capabilities(self._backend.get_capabilities())

    def _setup(self) -> None:
        """Initialize the sandbox backend."""
        explicit_backend = self.config.backend is not None
        backend_type = self.config.backend or self._detect_best_backend(self.config)
        self._backend = self._create_backend(backend_type)
        self._backend_type = backend_type
        try:
            self._backend.setup()
        except SandboxSetupError as exc:
            if not explicit_backend and backend_type is SandboxBackend.WINDOWS_APPCONTAINER:
                disable_windows_appcontainer_auto(str(exc))
            if (
                not explicit_backend
                and backend_type is SandboxBackend.WINDOWS_APPCONTAINER
                and check_wasm_support(self.config)
            ):
                self._backend = self._create_backend(SandboxBackend.WASM)
                self._backend_type = SandboxBackend.WASM
                self._backend.setup()
                backend_type = SandboxBackend.WASM
            else:
                raise

        required = self.config.required_capabilities
        if required is None:
            required = strict_default_required_capabilities()
        actual = self._backend.get_capabilities()
        missing = missing_capabilities(required, actual)
        if missing:
            self._backend.cleanup()
            self._backend = None
            self._backend_type = None
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
                logger.debug("Sandbox backend cleanup failed", exc_info=True)
        self._backend = None
        self._backend_type = None
        self._active = False

    @staticmethod
    def _detect_best_backend(config: SandboxConfig | None = None) -> SandboxBackend:
        """Auto-detect the most secure available backend."""
        if sys.platform == "linux":
            if check_linux_namespace_support():
                return SandboxBackend.LINUX_NAMESPACE

        if sys.platform == "win32":
            if check_windows_appcontainer_support():
                return SandboxBackend.WINDOWS_APPCONTAINER
            if check_wasm_support(config):
                return SandboxBackend.WASM

        if check_wasm_support(config):
            return SandboxBackend.WASM

        if sys.platform == "darwin":
            from pysymex.logger import get_logger

            get_logger(__name__).warning(
                "warning, no strong pysymex sandbox backend is configured on MacOS"
            )

        raise SandboxSetupError(
            "No strong pysymex sandbox backend is available. Configure Windows "
            "AppContainer, Linux namespace isolation, or WASM."
        )

    def _create_backend(self, backend_type: SandboxBackend) -> IsolationBackend:
        """Create the appropriate isolation backend."""
        if backend_type == SandboxBackend.LINUX_NAMESPACE:
            from .isolation.linux import LinuxNamespaceBackend

            return LinuxNamespaceBackend(self.config)

        if backend_type == SandboxBackend.WINDOWS_APPCONTAINER:
            from .isolation.windows.appcontainer.backend import WindowsAppContainerBackend

            return WindowsAppContainerBackend(self.config)

        if backend_type == SandboxBackend.WASM:
            from .isolation.wasm import WasmBackend

            return WasmBackend(self.config)

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

        validate_sandbox_filename(target_name)

        sanitized_files = sanitize_extra_files(extra_files)
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

        validate_sandbox_filename(filename)

        if isinstance(code, str):
            code_bytes = code.encode("utf-8")
        else:
            code_bytes = code

        sanitized_files = sanitize_extra_files(extra_files)
        _enforce_extra_file_limits(sanitized_files, self.config.limits)

        return self._backend.execute(
            code=code_bytes,
            filename=filename,
            input_data=input_data or b"",
            extra_files=sanitized_files,
        )

    def reset_workspace(self) -> None:
        """Reset transient sandbox workspace files when the backend supports it."""
        if not self._active or self._backend is None:
            raise SandboxError("Sandbox is not active. Use 'with SecureSandbox() as sb:' syntax.")
        reset = getattr(self._backend, "reset_workspace", None)
        if callable(reset):
            backend = cast(_WorkspaceResetBackend, self._backend)
            backend.reset_workspace()


SecureSandbox = SandboxRunner
