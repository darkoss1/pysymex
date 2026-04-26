from __future__ import annotations

import sys
from unittest.mock import patch

from pysymex.execution.opcodes import (
    _detect_python_version,
    _validate_version,
    _route_to_opcode_dir,
    py311,
    py312,
    py313,
)


def test_detect_python_version() -> None:
    """Test _detect_python_version returns expected tuple."""
    version = _detect_python_version()
    assert version == (sys.version_info.major, sys.version_info.minor)


def test_validate_version_supported() -> None:
    """Test _validate_version with supported version."""
    assert _validate_version((3, 12)) is True


def test_validate_version_unsupported_old() -> None:
    """Test _validate_version with unsupported older version."""
    assert _validate_version((3, 10)) is False


def test_validate_version_unsupported_new() -> None:
    """Test _validate_version with unsupported newer version."""
    assert _validate_version((3, 14)) is False


def test_route_to_opcode_dir_311() -> None:
    """Test _route_to_opcode_dir routes to 3.11."""
    module = _route_to_opcode_dir((3, 11))
    assert module is py311


def test_route_to_opcode_dir_312() -> None:
    """Test _route_to_opcode_dir routes to 3.12."""
    module = _route_to_opcode_dir((3, 12))
    assert module is py312


def test_route_to_opcode_dir_313() -> None:
    """Test _route_to_opcode_dir routes to 3.13."""
    module = _route_to_opcode_dir((3, 13))
    assert module is py313


def test_route_to_opcode_dir_newer() -> None:
    """Test _route_to_opcode_dir routes to max supported version."""
    module = _route_to_opcode_dir((3, 15))
    assert module is py313


def test_route_to_opcode_dir_unsupported() -> None:
    """Test _route_to_opcode_dir raises on too old version."""
    try:
        _route_to_opcode_dir((3, 10))
        assert False, "Should have raised ImportError"
    except ImportError:
        pass
