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

"""Opcode handler registration and Python-version routing for the VM.

Selects the ``py311`` / ``py312`` / ``py313`` handler packages matching the host
interpreter, imports them so
:class:`~pysymex.execution.dispatch.dispatcher.OpcodeDispatcher` decorator
registrations materialize, and clears stale global handlers on reload.
Called from executor startup before bytecode stepping; does not implement per-opcode
semantics (see :mod:`pysymex.execution.opcodes.common` and version subpackages).
"""

from pysymex.logger import get_logger
import sys
from importlib import import_module, reload
from types import ModuleType
from threading import Lock

from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher

logger = get_logger(__name__)

SUPPORTED_VERSIONS = [(3, 11), (3, 12), (3, 13)]
MIN_VERSION = (3, 11)
MAX_VERSION = (3, 13)
_handlers_lock = Lock()
_handlers_loaded = False
_loaded_module_name: str | None = None


def _registered_handlers_match(module_name: str) -> bool:
    """Return True when global opcode handlers point at the active version package."""
    handler_module = OpcodeDispatcher.global_handler_module("STORE_FAST")
    if handler_module is None:
        return False
    return handler_module.startswith(module_name)


def _refresh_version_handlers(module: ModuleType) -> None:
    """Reload version submodules so decorator-based global handlers are current."""
    exported_names = getattr(module, "__all__", ())
    for export_name in exported_names:
        if module.__name__ == "pysymex.execution.opcodes.py313" and export_name == "async_ops":
            continue
        exported = getattr(module, export_name, None)
        if isinstance(exported, ModuleType):
            reload(exported)


def detect_python_version() -> tuple[int, int]:
    """Detect the current Python version.

    Returns:
        Tuple of (major, minor) version numbers.
    """
    return (sys.version_info.major, sys.version_info.minor)


def validate_version(version: tuple[int, int]) -> bool:
    """Validate that the Python version is supported.

    Args:
        version: Tuple of (major, minor) version numbers.

    Returns:
        True if version is supported, False otherwise.
    """
    if version < MIN_VERSION:
        logger.error(
            f"Python {version[0]}.{version[1]} is not supported. Minimum version: {MIN_VERSION[0]}.{MIN_VERSION[1]}"
        )
        return False
    if version > MAX_VERSION:
        logger.error(
            f"Python {version[0]}.{version[1]} is not supported. Maximum version: {MAX_VERSION[0]}.{MAX_VERSION[1]}"
        )
        return False
    return True


def route_to_opcode_dir(version: tuple[int, int]) -> ModuleType:
    """Route to the appropriate opcode directory based on Python version.

    Args:
        version: Tuple of (major, minor) version numbers.

    Returns:
        The opcode module for the detected version.

    Raises:
        ImportError: If the version is not supported or module cannot be imported.
    """
    if not validate_version(version):
        raise ImportError(
            f"Python {version[0]}.{version[1]} is not supported by pysymex. "
            f"Supported versions: {MIN_VERSION[0]}.{MIN_VERSION[1]} through "
            f"{MAX_VERSION[0]}.{MAX_VERSION[1]}"
        )

    if version[1] >= 13:
        logger.info(f"Detected Python {version[0]}.{version[1]}, routing to py313 opcodes")
        from pysymex.execution.opcodes import py313 as py_version
    elif version[1] >= 12:
        logger.info(f"Detected Python {version[0]}.{version[1]}, routing to py312 opcodes")
        from pysymex.execution.opcodes import py312 as py_version
    else:
        logger.info(f"Detected Python {version[0]}.{version[1]}, routing to py311 opcodes")
        from pysymex.execution.opcodes import py311 as py_version

    return py_version


def _normalize_supported_version(version: tuple[int, int]) -> tuple[int, int]:
    """Normalize Python version to the closest supported opcode version."""
    if version < MIN_VERSION:
        raise ImportError(
            f"Python {version[0]}.{version[1]} is not supported by pysymex. "
            f"Supported versions: {MIN_VERSION[0]}.{MIN_VERSION[1]} through "
            f"{MAX_VERSION[0]}.{MAX_VERSION[1]}"
        )
    if version > MAX_VERSION:
        raise ImportError(
            f"Python {version[0]}.{version[1]} is not supported by pysymex. "
            f"Supported versions: {MIN_VERSION[0]}.{MIN_VERSION[1]} through "
            f"{MAX_VERSION[0]}.{MAX_VERSION[1]}"
        )
    return version


def load_opcode_handlers(version: tuple[int, int] | None = None) -> ModuleType:
    """Load opcode handler modules for a target Python version.

    This function guarantees that decorator-based opcode registrations are
    materialized before bytecode execution starts.
    """
    global _handlers_loaded
    global _loaded_module_name

    requested_version = version if version is not None else detect_python_version()
    target_version = _normalize_supported_version(requested_version)
    module_map = {
        11: "pysymex.execution.opcodes.py311",
        12: "pysymex.execution.opcodes.py312",
        13: "pysymex.execution.opcodes.py313",
    }
    module_name = module_map[target_version[1]]

    with _handlers_lock:
        module = import_module(module_name)
        if (
            _handlers_loaded
            and _loaded_module_name == module_name
            and _registered_handlers_match(module_name)
        ):
            return module
        OpcodeDispatcher.clear_global_handlers(("pysymex.execution.opcodes.",))
        _refresh_version_handlers(module)
        if target_version == (3, 12):
            instrumentation = import_module("pysymex.execution.opcodes.py312.instrumentation")
            reload(instrumentation)
        _handlers_loaded = True
        _loaded_module_name = module_name
        return module


__all__ = [
    "load_opcode_handlers",
    "detect_python_version",
    "validate_version",
    "route_to_opcode_dir",
]
