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
:class:`~pysymex._internal.execution.dispatch.dispatcher.OpcodeDispatcher` decorator
registrations materialize, and clears stale global handlers on reload.
Called from executor startup before bytecode stepping; does not implement per-opcode
semantics (see :mod:`pysymex._internal.execution.opcodes.common` and version subpackages).
"""

import pkgutil
import sys
from importlib import import_module, reload
from threading import Lock
from types import ModuleType

from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)

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
    """Reload version handler modules so decorator registrations are current."""
    package_path = getattr(module, "__path__", None)
    if package_path is None:
        if module.__name__ in sys.modules:
            reload(module)
        else:
            import_module(module.__name__)
        return

    for module_info in pkgutil.walk_packages(package_path, f"{module.__name__}."):
        handler_module = sys.modules.get(module_info.name)
        if handler_module is not None:
            reload(handler_module)
        else:
            import_module(module_info.name)


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
            f"Python {version[0]}.{version[1]} is not supported. Minimum version: {MIN_VERSION[0]}.{MIN_VERSION[1]}",
        )
        return False
    if version > MAX_VERSION:
        logger.error(
            f"Python {version[0]}.{version[1]} is not supported. Maximum version: {MAX_VERSION[0]}.{MAX_VERSION[1]}",
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
        msg = (
            f"Python {version[0]}.{version[1]} is not supported by pysymex. "
            f"Supported versions: {MIN_VERSION[0]}.{MIN_VERSION[1]} through "
            f"{MAX_VERSION[0]}.{MAX_VERSION[1]}"
        )
        raise ImportError(
            msg,
        )

    if version[1] >= 13:
        logger.info(f"Detected Python {version[0]}.{version[1]}, routing to py313 opcodes")
        from pysymex._internal.execution.opcodes import py313

        return py313
    if version[1] >= 12:
        logger.info(f"Detected Python {version[0]}.{version[1]}, routing to py312 opcodes")
        from pysymex._internal.execution.opcodes import py312

        return py312
    logger.info(f"Detected Python {version[0]}.{version[1]}, routing to py311 opcodes")
    from pysymex._internal.execution.opcodes import py311

    return py311


def _normalize_supported_version(version: tuple[int, int]) -> tuple[int, int]:
    """Normalize Python version to the closest supported opcode version."""
    if version < MIN_VERSION:
        msg = (
            f"Python {version[0]}.{version[1]} is not supported by pysymex. "
            f"Supported versions: {MIN_VERSION[0]}.{MIN_VERSION[1]} through "
            f"{MAX_VERSION[0]}.{MAX_VERSION[1]}"
        )
        raise ImportError(
            msg,
        )
    if version > MAX_VERSION:
        msg = (
            f"Python {version[0]}.{version[1]} is not supported by pysymex. "
            f"Supported versions: {MIN_VERSION[0]}.{MIN_VERSION[1]} through "
            f"{MAX_VERSION[0]}.{MAX_VERSION[1]}"
        )
        raise ImportError(
            msg,
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
        11: "pysymex._internal.execution.opcodes.py311",
        12: "pysymex._internal.execution.opcodes.py312",
        13: "pysymex._internal.execution.opcodes.py313",
    }
    module_name = module_map[target_version[1]]

    with _handlers_lock:
        module = import_module(module_name)
        if _registered_handlers_match(module_name):
            _handlers_loaded = True
            _loaded_module_name = module_name
            return module

        OpcodeDispatcher.clear_global_handlers(("pysymex._internal.execution.opcodes.",))
        _refresh_version_handlers(module)
        _handlers_loaded = True
        _loaded_module_name = module_name
        return module
