"""Shared detector audit manifest used by registry coverage tests."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectorAuditCase:
    """One expected detector outcome in the audit manifest."""

    detector_name: str
    expected_detected: bool


ALL_AUDIT_CASES: tuple[DetectorAuditCase, ...] = (
    DetectorAuditCase("assertion-error", True),
    DetectorAuditCase("assertion-error", False),
    DetectorAuditCase("attribute-error", True),
    DetectorAuditCase("attribute-error", False),
    DetectorAuditCase("division-by-zero", True),
    DetectorAuditCase("division-by-zero", False),
    DetectorAuditCase("index-error", True),
    DetectorAuditCase("index-error", False),
    DetectorAuditCase("key-error", True),
    DetectorAuditCase("key-error", False),
    DetectorAuditCase("none-dereference", True),
    DetectorAuditCase("none-dereference", False),
    DetectorAuditCase("overflow", True),
    DetectorAuditCase("overflow", False),
    DetectorAuditCase("resource-leak", True),
    DetectorAuditCase("resource-leak", False),
    DetectorAuditCase("type-error", True),
    DetectorAuditCase("type-error", False),
    DetectorAuditCase("unbound-variable", True),
    DetectorAuditCase("unbound-variable", False),
    DetectorAuditCase("user_exception", True),
    DetectorAuditCase("user_exception", False),
    DetectorAuditCase("value-error", True),
    DetectorAuditCase("value-error", False),
    DetectorAuditCase("infinite-loop", True),
    DetectorAuditCase("infinite-loop", False),
    DetectorAuditCase("use-after-free", True),
    DetectorAuditCase("use-after-free", False),
    DetectorAuditCase("format-string", True),
    DetectorAuditCase("format-string", False),
)
