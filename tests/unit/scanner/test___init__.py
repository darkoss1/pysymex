"""Scanner implementation package privacy."""

from __future__ import annotations

from pathlib import Path

import pysymex


def test_scanner_root_does_not_compete_with_public_scan_namespace() -> None:
    package_root = Path(pysymex.__file__).parent
    assert not (package_root / "scanner").exists()
    assert not hasattr(pysymex, "scanner")
    assert not hasattr(pysymex, "scan_file")
    assert not hasattr(pysymex, "scan_directory")
