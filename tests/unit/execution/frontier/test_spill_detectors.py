from __future__ import annotations

from typing import cast

import pytest
import z3

from pysymex.analysis.detectors import Issue, IssueKind, Severity
from pysymex.core.state.deferred import DeferredStateIssue
from pysymex.execution.detectors import DeferredDetectorIssue
from pysymex.execution.frontier.spill.detectors import (
    SpillDetectorDecodeError,
    decode_detector_issues,
    detector_issues_payload,
)


def _issue() -> Issue:
    return Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="possible zero divisor",
        pc=7,
        line_number=12,
        function_name="target",
        filename="target.py",
        stack_trace=("target.py:12",),
        class_name="Owner",
        full_path="Owner.target",
        counterexample={"x": 0, "path": ["left", "right"]},
        is_caught=True,
        confidence=0.5,
        likelihood=0.75,
        severity=Severity.HIGH,
        file="target.py",
        line=12,
        column=4,
        explanation="divisor can be zero",
        related_code="10 // x",
        fix_suggestion="guard x",
        detector_name="division",
        suppression_reason="pending context manager",
    )


def _payload() -> dict[str, object]:
    payloads = detector_issues_payload(
        (DeferredDetectorIssue(_issue(), (101, 7, IssueKind.DIVISION_BY_ZERO)),)
    )
    assert payloads is not None
    payload = payloads[0]
    assert isinstance(payload, dict)
    return cast("dict[str, object]", payload)


def test_detector_spill_payload_round_trips_model_free_issue_metadata() -> None:
    """Model-free detector sidecars round-trip through JSON-safe metadata."""
    decoded = decode_detector_issues([_payload()])

    assert decoded == [DeferredDetectorIssue(_issue(), (101, 7, IssueKind.DIVISION_BY_ZERO))]


def test_detector_spill_payload_accepts_optional_issue_metadata() -> None:
    """Optional detector fields survive as absent evidence."""
    issue = Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="optional metadata",
        pc=7,
        file="target.py",
        line=12,
    )
    payloads = detector_issues_payload(
        (DeferredDetectorIssue(issue, (101, 7, IssueKind.DIVISION_BY_ZERO)),)
    )
    assert payloads is not None

    decoded = decode_detector_issues(payloads)
    decoded_issue = cast("DeferredDetectorIssue", decoded[0]).issue

    assert decoded_issue.severity is None
    assert decoded_issue.counterexample is None


def test_detector_spill_payload_accepts_empty_issue_collections() -> None:
    """Empty sidecar collections are valid and decode as no pending issues."""
    assert detector_issues_payload(()) == []
    assert decode_detector_issues(None) == []


def test_detector_spill_payload_rejects_unsupported_sidecars() -> None:
    """Sidecars with unsupported payloads or solver evidence remain live."""
    symbol = z3.Int("spill_detector_unsupported")
    solver = z3.Solver()
    solver.add(symbol == 1)
    assert solver.check() == z3.sat

    unsupported = (
        DeferredStateIssue(issue="raw", site_key=("site",)),
        DeferredDetectorIssue(cast("Issue", object()), (101, 7, IssueKind.DIVISION_BY_ZERO)),
        DeferredDetectorIssue(
            Issue(
                kind=IssueKind.DIVISION_BY_ZERO,
                message="constraint-backed",
                constraints=[symbol == 0],
            ),
            (101, 7, IssueKind.DIVISION_BY_ZERO),
        ),
        DeferredDetectorIssue(
            Issue(
                kind=IssueKind.DIVISION_BY_ZERO,
                message="model-backed",
                model=solver.model(),
            ),
            (101, 7, IssueKind.DIVISION_BY_ZERO),
        ),
        DeferredDetectorIssue(
            Issue(
                kind=IssueKind.DIVISION_BY_ZERO,
                message="non-json counterexample",
                counterexample={"bad": object()},
            ),
            (101, 7, IssueKind.DIVISION_BY_ZERO),
        ),
    )

    for deferred in unsupported:
        assert detector_issues_payload((deferred,)) is None


def test_detector_spill_payload_rejects_bool_site_key_numbers() -> None:
    """Detector site keys reject bools masquerading as instruction IDs or PCs."""
    issue = _issue()
    bool_instruction_id = cast(
        "tuple[int, int, IssueKind]",
        (True, 7, IssueKind.DIVISION_BY_ZERO),
    )
    bool_pc = cast(
        "tuple[int, int, IssueKind]",
        (101, False, IssueKind.DIVISION_BY_ZERO),
    )

    assert detector_issues_payload((DeferredDetectorIssue(issue, bool_instruction_id),)) is None
    assert detector_issues_payload((DeferredDetectorIssue(issue, bool_pc),)) is None


@pytest.mark.parametrize(
    "raw_issues",
    [
        {"bad": "container"},
        [{"kind": "wrong"}],
        [
            {
                "kind": "deferred_detector_issue",
                "issue": [],
                "site_key": [101, 7, "DIVISION_BY_ZERO"],
            }
        ],
        [{"kind": "deferred_detector_issue", "issue": {}, "site_key": "bad"}],
        [{1: "bad"}],
    ],
)
def test_decode_detector_issues_rejects_malformed_top_level_payloads(
    raw_issues: object,
) -> None:
    """Malformed top-level detector sidecar payloads fail closed."""
    with pytest.raises(SpillDetectorDecodeError):
        decode_detector_issues(raw_issues)


@pytest.mark.parametrize(
    "site_key",
    [
        [101, 7],
        [True, 7, "DIVISION_BY_ZERO"],
        [101, False, "DIVISION_BY_ZERO"],
        [101, 7, 3],
        [101, 7, "NO_SUCH_KIND"],
    ],
)
def test_decode_detector_issues_rejects_malformed_site_keys(site_key: object) -> None:
    """Malformed site keys never reconstruct detector sidecars."""
    payload = _payload()
    payload["site_key"] = site_key

    with pytest.raises(SpillDetectorDecodeError):
        decode_detector_issues([payload])


def test_decode_detector_issues_rejects_non_list_site_key_after_valid_issue() -> None:
    """Malformed site-key containers are rejected after issue metadata decodes."""
    payload = _payload()
    payload["site_key"] = "bad"

    with pytest.raises(SpillDetectorDecodeError):
        decode_detector_issues([payload])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "NO_SUCH_KIND"),
        ("message", None),
        ("pc", True),
        ("pc", None),
        ("line_number", True),
        ("line_number", "bad"),
        ("function_name", 1),
        ("stack_trace", "bad"),
        ("stack_trace", [1]),
        ("counterexample", "bad"),
        ("counterexample", {1: "bad"}),
        ("is_caught", "yes"),
        ("confidence", True),
        ("confidence", "bad"),
        ("severity", 1),
        ("severity", "NO_SUCH_SEVERITY"),
    ],
)
def test_decode_detector_issues_rejects_malformed_issue_fields(
    field: str,
    value: object,
) -> None:
    """Malformed issue metadata never reconstructs partial detector evidence."""
    payload = _payload()
    issue_payload = cast("dict[str, object]", payload["issue"])
    issue_payload[field] = value

    with pytest.raises(SpillDetectorDecodeError):
        decode_detector_issues([payload])
