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

"""Discover the WASI Python artifact used by the WebAssembly backend.

This module resolves explicitly configured or package-bundled runtime
artifacts and reports whether the optional Wasmtime dependency is available.
It does not instantiate or execute a WebAssembly sandbox.
"""

from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path
from typing import TYPE_CHECKING, Final

from pysymex.logger import get_logger

if TYPE_CHECKING:
    from ...types import SandboxConfig

_BUNDLED_WASI_PYTHON_CANDIDATES: Final[tuple[str, ...]] = (
    "python.wasm",
    "python-wasi.wasm",
    "python3.wasm",
)

logger = get_logger(__name__)


def resolve_wasm_python_module(config: SandboxConfig) -> Path | None:
    """Resolve the WASI Python module used by ``WasmBackend``.

    Resolution is deliberately capability-based:
    - an explicit ``SandboxConfig.wasm_python_module`` path, or
    - a bundled artifact shipped under ``pysymex/sandbox/assets``.

    Ambient environment variables and the caller's working directory are not
    consulted because backend strength must not depend on host process state.
    """
    configured = config.wasm_python_module
    if configured is not None:
        path = Path(configured)
        if path.is_file():
            return path.resolve()
        logger.debug("Configured WASI Python module is not a file: %s", path)
        return None

    assets_dir = Path(__file__).resolve().parents[1] / "assets"
    for candidate in _BUNDLED_WASI_PYTHON_CANDIDATES:
        path = assets_dir / candidate
        if path.is_file():
            return path.resolve()
    logger.debug("No bundled WASI Python module found in %s", assets_dir)
    return None


def has_wasm_runtime_support(config: SandboxConfig) -> bool:
    """Return whether Wasmtime and a WASI Python artifact are discoverable.

    Args:
        config: Sandbox configuration used to resolve an explicit or bundled
            WASI Python module.

    Returns:
        Whether the optional Wasmtime package is importable and a runtime
        artifact can be resolved.

    Limitations:
        This availability check does not instantiate the backend or verify its
        execution boundary.
    """
    return find_spec("wasmtime") is not None and resolve_wasm_python_module(config) is not None
