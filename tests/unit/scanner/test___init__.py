"""Tests for scanner package exports."""

from __future__ import annotations

import pytest

import pysymex.scanner


class TestScannerInit:
    """Test class for scanner package initialization."""

    def test_scanner_init_getattr_resolves_symbol(self) -> None:
        """Verify __getattr__ dynamically resolves exported symbols like scan_file."""
        assert hasattr(pysymex.scanner, "scan_file")
        assert callable(pysymex.scanner.scan_file)

    def test_scanner_init_getattr_raises_attribute_error(self) -> None:
        """Verify __getattr__ raises AttributeError for unknown symbols."""
        with pytest.raises(AttributeError, match="has no attribute"):
            _ = pysymex.scanner.this_symbol_does_not_exist  # type: ignore[attr-defined] # testing missing attr

    def test_scanner_init_dir_lists_exports(self) -> None:
        """Verify __dir__ lists the contents of the module's defined exports."""
        exports = dir(pysymex.scanner)
        assert "scan_file" in exports
        assert "scan_directory" in exports
        assert "ScanSession" in exports
