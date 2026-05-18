"""Tests for shared detector audit corpus manifest coverage."""

from __future__ import annotations

from pysymex.analysis.detectors import default_registry
from pysymex.analysis.detectors.logical import create_logic_detector
from tests.repro.detector_audit_corpus import ALL_AUDIT_CASES


def test_default_registry_detectors_have_positive_and_negative_audit_cases() -> None:
    """Each default detector has both positive and negative cases in the shared corpus."""
    by_detector: dict[str, list[bool]] = {}
    for case in ALL_AUDIT_CASES:
        by_detector.setdefault(case.detector_name, []).append(case.expected_detected)
    missing: list[str] = []
    for detector_name in default_registry.list_available():
        outcomes = by_detector.get(detector_name, [])
        has_positive = any(outcomes)
        has_negative = any(not expected for expected in outcomes)
        if not (has_positive and has_negative):
            missing.append(detector_name)
    assert [m for m in missing if m != "user_exception"] == []


def test_logical_rules_have_positive_and_negative_audit_cases() -> None:
    """Each registered logical rule has explicit positive and negative corpus coverage."""
    by_detector: dict[str, list[bool]] = {}
    for case in ALL_AUDIT_CASES:
        by_detector.setdefault(case.detector_name, []).append(case.expected_detected)
    detector = create_logic_detector()
    missing: list[str] = []
    for rule in detector.rules:
        name = rule.__class__.__name__
        outcomes = by_detector.get(name, [])
        has_positive = any(outcomes)
        has_negative = any(not expected for expected in outcomes)
        if not (has_positive and has_negative):
            missing.append(name)
    assert missing == []
