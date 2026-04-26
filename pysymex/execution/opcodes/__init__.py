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

"""Opcode handlers module.
This module provides intelligent Python version detection and routing
to the appropriate opcode directory for the running Python version.
"""

import logging
import sys
from types import ModuleType

logger = logging.getLogger(__name__)

SUPPORTED_VERSIONS = [(3, 11), (3, 12), (3, 13)]
MIN_VERSION = (3, 11)
MAX_VERSION = (3, 13)


def _detect_python_version() -> tuple[int, int]:
    """Detect the current Python version.

    Returns:
        Tuple of (major, minor) version numbers.
    """
    return (sys.version_info.major, sys.version_info.minor)


def _validate_version(version: tuple[int, int]) -> bool:
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
        logger.warning(
            f"Python {version[0]}.{version[1]} is newer than maximum supported version {MAX_VERSION[0]}.{MAX_VERSION[1]}. Using {MAX_VERSION[0]}.{MAX_VERSION[1]} opcodes."
        )
        return False
    return True


def _route_to_opcode_dir(version: tuple[int, int]) -> ModuleType:
    """Route to the appropriate opcode directory based on Python version.

    Args:
        version: Tuple of (major, minor) version numbers.

    Returns:
        The opcode module for the detected version.

    Raises:
        ImportError: If the version is not supported or module cannot be imported.
    """
    if not _validate_version(version):
        if version < MIN_VERSION:
            raise ImportError(
                f"Python {version[0]}.{version[1]} is not supported by pysymex. "
                f"Minimum required version: {MIN_VERSION[0]}.{MIN_VERSION[1]}"
            )
        version = MAX_VERSION

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


# Detect version and route
_detected_version = _detect_python_version()
py_version = _route_to_opcode_dir(_detected_version)

__all__ = [
    "py_version",
    "_detect_python_version",
    "_validate_version",
    "_route_to_opcode_dir",
]
