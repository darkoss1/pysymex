# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Isolation backend base classes and interfaces.

This module defines the abstract interface that all isolation
backends must implement.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from .._types import SecurityCapabilities

if TYPE_CHECKING:
    from .._types import SandboxConfig, SandboxResult


class IsolationBackend(ABC):
    """Abstract base class for sandbox isolation backends.

    Each backend implements platform-specific isolation mechanisms.
    Backends must implement setup(), cleanup(), and execute() methods.

    The isolation backend is responsible for:
        1. Creating the isolated execution environment
        2. Copying files into the sandbox jail
        3. Executing code with appropriate restrictions
        4. Capturing output and resource usage
        5. Cleaning up all resources on exit

    Attributes:
        config: The sandbox configuration
        name: Human-readable backend name
    """

    def __init__(self, config: SandboxConfig) -> None:
        """Initialize the backend with configuration.

        Args:
            config: Sandbox configuration specifying limits and options
        """
        self.config = config
        self._jail_path: Path | None = None
        self._is_setup: bool = False

    @property
    def name(self) -> str:
        """Human-readable name for this backend."""
        return self.__class__.__name__

    @property
    def jail_path(self) -> Path | None:
        """Path to the filesystem jail (if set up)."""
        return self._jail_path

    @property
    def is_setup(self) -> bool:
        """Whether the backend has been set up."""
        return self._is_setup

    def _create_jail(self) -> Path:
        """Create a unique, ephemeral jail directory.

        Returns:
            Absolute path to the newly created jail directory.

        Raises:
            OSError: If directory creation fails.
        """
        base_dir: Path = (
            Path(self.config.working_directory)
            if self.config.working_directory
            else Path(tempfile.gettempdir())
        )
        base_dir.mkdir(parents=True, exist_ok=True)
        jail = base_dir / f"pysymex_sandbox_{time.time_ns()}"
        jail.mkdir(parents=False, exist_ok=False)
        return jail

    def _destroy_jail(self) -> None:
        """Remove the jail directory and all contents (best-effort)."""
        if self._jail_path is not None and self._jail_path.exists():
            shutil.rmtree(self._jail_path, ignore_errors=True)
        self._jail_path = None

    def _populate_jail(
        self,
        code: bytes,
        filename: str,
        extra_files: dict[str, bytes],
    ) -> None:
        """Write target code and supplementary files into the jail.

        Args:
            code: Target Python source code as bytes.
            filename: Filename under which *code* is stored.
            extra_files: Additional files ``{relative_path: content}``.
        """
        if self._jail_path is None:
            msg = "Jail not created"
            raise RuntimeError(msg)

        (self._jail_path / filename).write_bytes(code)
        jail_root = self._jail_path.resolve()

        for rel_path, content in extra_files.items():
            out = self._jail_path / rel_path
            out_abs = out.resolve()
            if out_abs != jail_root and jail_root not in out_abs.parents:
                msg = f"Refusing to write outside sandbox jail: {rel_path!r}"
                raise ValueError(msg)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(content)

    def _python_exe(self) -> str:
        """Return the Python executable to use inside the sandbox."""
        return self.config.python_executable or sys.executable

    def _python_cmd(self) -> list[str]:
        """Return a hardened Python command prefix for sandboxed execution.

        Flags:
            -I: Isolated mode (ignores user site and most env influence)
            -B: Disable .pyc writes to reduce filesystem side effects
        """
        return [self._python_exe(), "-I", "-B"]

    def _clean_environment(self) -> dict[str, str]:
        """Build a minimal, sanitised environment for the subprocess.

        Strips dangerous injection variables and limits env leakage.
        """
        import os

        if sys.platform == "win32":
            env: dict[str, str] = {
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
                "COMSPEC": os.environ.get("COMSPEC", r"C:\Windows\system32\cmd.exe"),
                "PATH": (os.environ.get("SYSTEMROOT", r"C:\Windows") + r"\system32"),
            }
            if self._jail_path is not None:
                env["TEMP"] = str(self._jail_path)
                env["TMP"] = str(self._jail_path)
        else:
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": "/tmp",
                "LANG": "C.UTF-8",
            }

            env["PYTHONNOUSERSITE"] = "1"
            env["PYTHONDONTWRITEBYTECODE"] = "1"

        _DANGEROUS_VARS: frozenset[str] = frozenset(
            {
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
                "DYLD_INSERT_LIBRARIES",
                "DYLD_LIBRARY_PATH",
                "PYTHONPATH",
                "PYTHONSTARTUP",
                "PYTHONHOME",
            }
        )
        for key, value in self.config.environment.items():
            if key not in _DANGEROUS_VARS:
                env[key] = value

        return env

    @abstractmethod
    def setup(self) -> None:
        """Initialize the sandbox environment.

        This method is called once before any executions. It should:
            - Create the filesystem jail
            - Initialize any OS-level isolation mechanisms
            - Prepare the execution environment

        Raises:
            SandboxSetupError: If setup fails
        """
        ...

    @abstractmethod
    def cleanup(self) -> None:
        """Clean up all sandbox resources.

        This method is called when exiting the context manager.
        It should:
            - Remove the filesystem jail and all contents
            - Release any OS-level resources
            - Kill any lingering processes

        This method should not raise exceptions; cleanup failures
        should be logged but not propagated.
        """
        ...

    @abstractmethod
    def execute(
        self,
        code: bytes,
        filename: str,
        input_data: bytes,
        extra_files: dict[str, bytes],
    ) -> SandboxResult:
        """Execute code in the isolated environment.

        Args:
            code: Python source code to execute (as bytes)
            filename: Filename to use for the code
            input_data: Data to provide on stdin
            extra_files: Additional files to copy into sandbox
                (relative path -> content mapping)

        Returns:
            SandboxResult with execution status, outputs, and metrics

        Raises:
            SandboxError: If execution fails in an unexpected way
        """
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is available on the current system.

        Returns:
            True if the backend can be used, False otherwise
        """
        ...

    def get_capabilities(self) -> SecurityCapabilities:
        """Get the enforced security capabilities of this backend.

        Returns:
            A ``SecurityCapabilities`` instance describing which
            security features are **actually enforced** (not merely
            attempted) by this backend.
        """
        return SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=True,
        )
