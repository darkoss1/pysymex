"""Tests for specialized detector domain ops."""

from pysymex._internal.analysis.detectors.specialized.detector_ops import SpecializedDetectorOps


def test_display_name_exists() -> None:
    assert callable(SpecializedDetectorOps.display_name)


def test_target_name_exists() -> None:
    assert callable(SpecializedDetectorOps.target_name)
