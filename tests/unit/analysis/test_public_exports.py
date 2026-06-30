"""Analysis implementation package privacy."""

from __future__ import annotations

from pathlib import Path

import pysymex


def test_analysis_root_does_not_compete_with_public_analyze_namespace() -> None:
    package_root = Path(pysymex.__file__).parent
    assert not (package_root / "analysis").exists()
    assert not hasattr(pysymex, "analysis")
