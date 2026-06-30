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

"""Single source of truth for analysis outcome classification.

This module owns the whole result/failure/degradation taxonomy boundary.  Lower
layers may still use local exceptions, fallback events, solver telemetry, and
degraded-pass labels, but public execution/scan results must flow through this
policy before they become ``outcome``/``outcome_subreason``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, StrEnum, auto
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class AnalysisOutcome(StrEnum):
    """Stable top-level classification for an execution or scan result."""

    SAFE = "SAFE"
    ISSUE_FOUND = "ISSUE_FOUND"
    TARGET_EXCEPTION = "TARGET_EXCEPTION"
    DEGRADED = "DEGRADED"
    UNSUPPORTED = "UNSUPPORTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ENGINE_FAILURE = "ENGINE_FAILURE"


class OutcomeSubreason(StrEnum):
    """Stable subreason vocabulary for :class:`AnalysisOutcome`."""

    ZERO_DIVISION = "zero_division"
    MODULO_BY_ZERO = "modulo_by_zero"
    TYPE_ERROR = "type_error"
    VALUE_ERROR = "value_error"
    KEY_ERROR = "key_error"
    INDEX_ERROR = "index_error"
    ATTRIBUTE_ERROR = "attribute_error"
    NAME_ERROR = "name_error"
    UNBOUND_VARIABLE = "unbound_variable"
    ASSERTION_ERROR = "assertion_error"
    CONTRACT_VIOLATION = "contract_violation"
    RESOURCE_LEAK = "resource_leak"
    NULL_DEREFERENCE = "null_dereference"
    OVERFLOW = "overflow"
    INFINITE_LOOP = "infinite_loop"
    INVALID_ARGUMENT = "invalid_argument"
    TARGET_EXCEPTION = "target_exception"
    RUNTIME_ERROR = "runtime_error"
    UNKNOWN_ISSUE = "unknown_issue"

    UNSUPPORTED_OPCODE = "unsupported_opcode"
    UNSUPPORTED_COROUTINE = "unsupported_coroutine"
    UNSUPPORTED_DESCRIPTOR = "unsupported_descriptor"
    UNSUPPORTED_VM_STATE = "unsupported_vm_state"
    UNSUPPORTED_SEMANTICS = "unsupported_semantics"

    SOLVER_TIMEOUT = "solver_timeout"
    SOLVER_UNKNOWN = "solver_unknown"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    INTERRUPTED = "interrupted"

    HAVOC_FALLBACK = "havoc_fallback"
    APPROXIMATE_STDLIB = "approximate_stdlib"
    IMPRECISE_IMPORT = "imprecise_import"
    LOOP_WIDENING = "loop_widening"
    STATE_MERGER = "state_merger"
    FALSE_POSITIVE_FILTERING = "fp_filtering"
    DEGRADED_PRECISION = "degraded_precision"

    STACK_UNDERFLOW = "stack_underflow"
    VM_INVARIANT_ERROR = "vm_invariant_error"
    MODEL_CONTRACT_ERROR = "model_contract_error"
    SANDBOX_ERROR = "sandbox_error"
    SOLVER_BACKEND_ERROR = "solver_backend_error"
    ENGINE_CRASH = "engine_crash"


class IssueKind(Enum):
    """Issue kinds emitted by active PySyMex detectors and runtime diagnostics."""

    DIVISION_BY_ZERO = auto()
    MODULO_BY_ZERO = auto()
    ASSERTION_ERROR = auto()
    INDEX_ERROR = auto()
    KEY_ERROR = auto()
    TYPE_ERROR = auto()
    ATTRIBUTE_ERROR = auto()
    OVERFLOW = auto()
    NULL_DEREFERENCE = auto()
    INFINITE_LOOP = auto()
    UNHANDLED_EXCEPTION = auto()
    CONTRACT_VIOLATION = auto()
    INVALID_ARGUMENT = auto()
    RESOURCE_LEAK = auto()
    VALUE_ERROR = auto()
    UNBOUND_VARIABLE = auto()
    NAME_ERROR = auto()
    RUNTIME_ERROR = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class OutcomeEvidence:
    """Structured evidence consumed by :meth:`OutcomePolicy.classify`.

    This is the bridge between internal PySyMex subsystems and public outcome
    classification.  It lets VM failures, fallback events, solver limits, and
    infrastructure degradation reach the final result without fragile substring
    matching.  Degraded-pass labels are still accepted until all runtime
    degradation producers emit structured fallback evidence.
    """

    outcome: AnalysisOutcome
    subreason: OutcomeSubreason
    label: str
    source: str = "unknown"
    detail: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        """Serialize the evidence record into stable JSON-compatible fields."""
        return {
            "outcome": self.outcome.value,
            "subreason": self.subreason.value,
            "label": self.label,
            "source": self.source,
            "detail": self.detail,
        }


# Outcome precedence is trust-first: an execution that crashed, hit an unsupported
# semantic boundary, or became inconclusive must not be summarized as safe or as a
# clean finding.
_OUTCOME_PRECEDENCE: tuple[AnalysisOutcome, ...] = (
    AnalysisOutcome.ENGINE_FAILURE,
    AnalysisOutcome.UNSUPPORTED,
    AnalysisOutcome.INCONCLUSIVE,
    AnalysisOutcome.ISSUE_FOUND,
    AnalysisOutcome.TARGET_EXCEPTION,
    AnalysisOutcome.DEGRADED,
    AnalysisOutcome.SAFE,
)

_ISSUE_SUBREASONS: dict[str, OutcomeSubreason] = {
    "DIVISION_BY_ZERO": OutcomeSubreason.ZERO_DIVISION,
    "MODULO_BY_ZERO": OutcomeSubreason.MODULO_BY_ZERO,
    "ASSERTION_ERROR": OutcomeSubreason.ASSERTION_ERROR,
    "INDEX_ERROR": OutcomeSubreason.INDEX_ERROR,
    "KEY_ERROR": OutcomeSubreason.KEY_ERROR,
    "TYPE_ERROR": OutcomeSubreason.TYPE_ERROR,
    "ATTRIBUTE_ERROR": OutcomeSubreason.ATTRIBUTE_ERROR,
    "OVERFLOW": OutcomeSubreason.OVERFLOW,
    "NULL_DEREFERENCE": OutcomeSubreason.NULL_DEREFERENCE,
    "INFINITE_LOOP": OutcomeSubreason.INFINITE_LOOP,
    "CONTRACT_VIOLATION": OutcomeSubreason.CONTRACT_VIOLATION,
    "INVALID_ARGUMENT": OutcomeSubreason.INVALID_ARGUMENT,
    "RESOURCE_LEAK": OutcomeSubreason.RESOURCE_LEAK,
    "VALUE_ERROR": OutcomeSubreason.VALUE_ERROR,
    "UNBOUND_VARIABLE": OutcomeSubreason.UNBOUND_VARIABLE,
    "NAME_ERROR": OutcomeSubreason.NAME_ERROR,
    "RUNTIME_ERROR": OutcomeSubreason.RUNTIME_ERROR,
    "UNKNOWN": OutcomeSubreason.UNKNOWN_ISSUE,
}

_TARGET_EXCEPTION_KINDS = frozenset(("UNHANDLED_EXCEPTION",))
_TARGET_EXCEPTION_DETECTOR_NAMES = frozenset(("user_exception", "model-side-effect"))
_UNHANDLED_EXCEPTION_PREFIX = "Path raises unhandled exception:"


class OutcomePolicy:
    """Policy owner for execution and scan outcome classification."""

    @staticmethod
    def classify(
        issues: Sequence[dict[str, object] | object],
        degraded_passes: Sequence[str],
        outcome_evidence: Sequence[OutcomeEvidence | dict[str, object] | object] | None = None,
    ) -> tuple[AnalysisOutcome, str | None]:
        """Return the strongest honest outcome and stable subreason for one result."""
        return _classify_outcome(issues, degraded_passes, outcome_evidence)

    @staticmethod
    def evidence_from_exception(exc: BaseException, *, source: str = "engine") -> OutcomeEvidence:
        """Convert an escaping internal exception into structured outcome evidence."""
        return _evidence_from_exception(exc, source=source)

    @staticmethod
    def evidence_from_fallback_event(event: object) -> OutcomeEvidence:
        """Convert a structured fallback event into outcome evidence."""
        return _evidence_from_fallback_event(event)

    @staticmethod
    def evidence_from_fallback_events(events: Iterable[object]) -> list[OutcomeEvidence]:
        """Return outcome evidence records for all fallback events."""
        return [_evidence_from_fallback_event(event) for event in events]

    @staticmethod
    def serialize_evidence(
        evidence: Iterable[OutcomeEvidence | dict[str, object] | object],
    ) -> list[dict[str, str | None]]:
        """Serialize heterogeneous evidence records into stable dictionaries."""
        return [_normalize_evidence(item).to_dict() for item in evidence]


def _classify_outcome(
    issues: Sequence[dict[str, object] | object],
    degraded_passes: Sequence[str],
    outcome_evidence: Sequence[OutcomeEvidence | dict[str, object] | object] | None = None,
) -> tuple[AnalysisOutcome, str | None]:
    """Return the strongest honest outcome and stable subreason for one result.

    Precedence is intentionally global and explicit:

    ``ENGINE_FAILURE > UNSUPPORTED > INCONCLUSIVE > ISSUE_FOUND > TARGET_EXCEPTION
    > DEGRADED > SAFE``.

    Structured ``outcome_evidence`` is preferred over degraded-pass markers.
    """
    candidates: list[tuple[AnalysisOutcome, OutcomeSubreason | None]] = []

    if outcome_evidence:
        candidates.extend(_classify_outcome_evidence(outcome_evidence))

    candidates.extend(_classify_degraded_passes(degraded_passes))

    if issues:
        candidates.append(_classify_issues(issues))

    if not candidates:
        return AnalysisOutcome.SAFE, None

    for outcome in _OUTCOME_PRECEDENCE:
        for candidate_outcome, subreason in candidates:
            if candidate_outcome is outcome:
                return outcome, subreason.value if subreason is not None else None
    return AnalysisOutcome.SAFE, None


def _evidence_from_exception(exc: BaseException, *, source: str = "engine") -> OutcomeEvidence:
    """Convert an escaping internal exception into structured outcome evidence.

    The conversion is intentionally conservative: unexpected Python exceptions
    raised by PySyMex are engine failures, not target-program bugs.  Expected
    resource/interruption/unsupported boundaries are classified separately.
    """
    name = type(exc).__name__
    detail = str(exc)
    text = f"{name}: {detail}".lower()
    outcome, subreason = _classify_error(text)
    return OutcomeEvidence(
        outcome=outcome,
        subreason=subreason,
        label=_label_for_subreason(subreason),
        source=source,
        detail=f"{name}({detail})",
    )


def _evidence_from_fallback_event(event: object) -> OutcomeEvidence:
    """Convert a structured fallback event into outcome evidence.

    This function uses attribute/value protocols instead of importing execution
    fallback classes, keeping the core outcome layer independent from execution
    internals.
    """
    label = _event_str(event, "label") or "fallback_event"
    source = _event_str(event, "owner") or "fallback"
    detail = _event_str(event, "reason")
    soundness = _event_value(event, "soundness")
    kind = _event_value(event, "kind")

    if soundness == "unsupported" or kind == "unsupported":
        outcome = AnalysisOutcome.UNSUPPORTED
        subreason = _unsupported_subreason_for_label(label)
    elif soundness == "inconclusive" or kind in {"resource_limit", "unknown"}:
        outcome = AnalysisOutcome.INCONCLUSIVE
        subreason = _inconclusive_subreason_for_label(label)
    else:
        outcome, subreason = _classify_degraded_label(label)
        if outcome is AnalysisOutcome.UNSUPPORTED and soundness == "precision_loss":
            outcome = AnalysisOutcome.DEGRADED
            subreason = OutcomeSubreason.DEGRADED_PRECISION

    return OutcomeEvidence(
        outcome=outcome,
        subreason=subreason,
        label=label,
        source=source,
        detail=detail,
    )


def _classify_outcome_evidence(
    evidence: Sequence[OutcomeEvidence | dict[str, object] | object],
) -> list[tuple[AnalysisOutcome, OutcomeSubreason]]:
    """Classify structured outcome evidence records."""
    candidates: list[tuple[AnalysisOutcome, OutcomeSubreason]] = []
    for item in evidence:
        normalized = _normalize_evidence(item)
        candidates.append((normalized.outcome, normalized.subreason))
    return candidates


def _normalize_evidence(item: OutcomeEvidence | dict[str, object] | object) -> OutcomeEvidence:
    """Normalize dict/object evidence into :class:`OutcomeEvidence`."""
    if isinstance(item, OutcomeEvidence):
        return item
    if isinstance(item, dict):
        item_dict = cast("dict[str, object]", item)
        outcome = _coerce_outcome(item_dict.get("outcome"))
        subreason = _coerce_subreason(item_dict.get("subreason"))
        label = item_dict.get("label")
        source = item_dict.get("source")
        detail = item_dict.get("detail")
        return OutcomeEvidence(
            outcome=outcome,
            subreason=subreason,
            label=label if isinstance(label, str) else subreason.value,
            source=source if isinstance(source, str) else "unknown",
            detail=detail if isinstance(detail, str) else None,
        )
    outcome = _coerce_outcome(getattr(item, "outcome", None))
    subreason = _coerce_subreason(getattr(item, "subreason", None))
    label = getattr(item, "label", None)
    source = getattr(item, "source", None)
    detail = getattr(item, "detail", None)
    return OutcomeEvidence(
        outcome=outcome,
        subreason=subreason,
        label=label if isinstance(label, str) else subreason.value,
        source=source if isinstance(source, str) else "unknown",
        detail=detail if isinstance(detail, str) else None,
    )


def _coerce_outcome(value: object) -> AnalysisOutcome:
    """Coerce serialized/enum outcome values to :class:`AnalysisOutcome`."""
    if isinstance(value, AnalysisOutcome):
        return value
    text = _enum_or_string(value)
    try:
        return AnalysisOutcome(text)
    except ValueError:
        try:
            return AnalysisOutcome[text]
        except KeyError:
            return AnalysisOutcome.ENGINE_FAILURE


def _coerce_subreason(value: object) -> OutcomeSubreason:
    """Coerce serialized/enum subreason values to :class:`OutcomeSubreason`."""
    if isinstance(value, OutcomeSubreason):
        return value
    text = _enum_or_string(value)
    try:
        return OutcomeSubreason(text)
    except ValueError:
        try:
            return OutcomeSubreason[text]
        except KeyError:
            return OutcomeSubreason.ENGINE_CRASH


def _classify_error(error: str) -> tuple[AnalysisOutcome, OutcomeSubreason]:
    """Classify an escaping scanner/execution error."""
    err_lower = error.lower()
    if "keyboardinterrupt" in err_lower or "keyboard interrupt" in err_lower:
        return AnalysisOutcome.INCONCLUSIVE, OutcomeSubreason.INTERRUPTED
    if "timeout" in err_lower or "timed out" in err_lower:
        return AnalysisOutcome.INCONCLUSIVE, OutcomeSubreason.SOLVER_TIMEOUT
    if any(token in err_lower for token in ("memoryerror", "out of memory", "recursionerror")):
        return AnalysisOutcome.INCONCLUSIVE, OutcomeSubreason.RESOURCE_EXHAUSTED
    if any(token in err_lower for token in ("resource", "limit", "cap")):
        return AnalysisOutcome.INCONCLUSIVE, OutcomeSubreason.RESOURCE_EXHAUSTED
    if "z3exception" in err_lower or "solver backend" in err_lower:
        return AnalysisOutcome.ENGINE_FAILURE, OutcomeSubreason.SOLVER_BACKEND_ERROR
    if any(
        token in err_lower for token in ("unsupported", "not implemented", "notimplementederror")
    ):
        if "opcode" in err_lower:
            return AnalysisOutcome.UNSUPPORTED, OutcomeSubreason.UNSUPPORTED_OPCODE
        if "vmstate" in err_lower or "vm state" in err_lower:
            return AnalysisOutcome.UNSUPPORTED, OutcomeSubreason.UNSUPPORTED_VM_STATE
        return AnalysisOutcome.UNSUPPORTED, OutcomeSubreason.UNSUPPORTED_SEMANTICS
    if "stack underflow" in err_lower:
        return AnalysisOutcome.ENGINE_FAILURE, OutcomeSubreason.STACK_UNDERFLOW
    if (
        "stack corruption" in err_lower
        or "vmstateerror" in err_lower
        or "vm invariant" in err_lower
    ):
        return AnalysisOutcome.ENGINE_FAILURE, OutcomeSubreason.VM_INVARIANT_ERROR
    if "model contract" in err_lower or "contract error" in err_lower:
        return AnalysisOutcome.ENGINE_FAILURE, OutcomeSubreason.MODEL_CONTRACT_ERROR
    if "sandbox" in err_lower:
        return AnalysisOutcome.ENGINE_FAILURE, OutcomeSubreason.SANDBOX_ERROR
    return AnalysisOutcome.ENGINE_FAILURE, OutcomeSubreason.ENGINE_CRASH


def _classify_degraded_passes(
    degraded_passes: Iterable[str],
) -> list[tuple[AnalysisOutcome, OutcomeSubreason]]:
    """Classify all degradation/unsupported/inconclusive markers."""
    return [_classify_degraded_label(label) for label in degraded_passes]


def _classify_degraded_label(label: str) -> tuple[AnalysisOutcome, OutcomeSubreason]:
    """Classify one degradation marker into the outcome taxonomy."""
    text = label.lower()
    if "unsupported" in text:
        return AnalysisOutcome.UNSUPPORTED, _unsupported_subreason_for_label(label)
    if "timeout" in text or "timed out" in text:
        return AnalysisOutcome.INCONCLUSIVE, OutcomeSubreason.SOLVER_TIMEOUT
    if "solver_unknown" in text or "unknown" in text:
        return AnalysisOutcome.INCONCLUSIVE, OutcomeSubreason.SOLVER_UNKNOWN
    if any(token in text for token in ("limit", "cap", "resource")):
        return AnalysisOutcome.INCONCLUSIVE, OutcomeSubreason.RESOURCE_EXHAUSTED
    if "havoc" in text:
        return AnalysisOutcome.DEGRADED, OutcomeSubreason.HAVOC_FALLBACK
    if "stdlib" in text or "approximate" in text:
        return AnalysisOutcome.DEGRADED, OutcomeSubreason.APPROXIMATE_STDLIB
    if "import" in text:
        return AnalysisOutcome.DEGRADED, OutcomeSubreason.IMPRECISE_IMPORT
    if "loop_widening" in text:
        return AnalysisOutcome.DEGRADED, OutcomeSubreason.LOOP_WIDENING
    if "state_merger" in text:
        return AnalysisOutcome.DEGRADED, OutcomeSubreason.STATE_MERGER
    if "fp_filtering" in text:
        return AnalysisOutcome.DEGRADED, OutcomeSubreason.FALSE_POSITIVE_FILTERING
    return AnalysisOutcome.DEGRADED, OutcomeSubreason.DEGRADED_PRECISION


def _unsupported_subreason_for_label(label: str) -> OutcomeSubreason:
    """Return a precise unsupported subreason for a label."""
    text = label.lower()
    if "opcode" in text:
        return OutcomeSubreason.UNSUPPORTED_OPCODE
    if "coroutine" in text or "await" in text or "generator" in text:
        return OutcomeSubreason.UNSUPPORTED_COROUTINE
    if "descriptor" in text or "property" in text:
        return OutcomeSubreason.UNSUPPORTED_DESCRIPTOR
    if "vm_state" in text or "vm state" in text:
        return OutcomeSubreason.UNSUPPORTED_VM_STATE
    return OutcomeSubreason.UNSUPPORTED_SEMANTICS


def _inconclusive_subreason_for_label(label: str) -> OutcomeSubreason:
    """Return a precise inconclusive subreason for a label."""
    text = label.lower()
    if "timeout" in text or "timed out" in text:
        return OutcomeSubreason.SOLVER_TIMEOUT
    if any(token in text for token in ("limit", "cap", "resource")):
        return OutcomeSubreason.RESOURCE_EXHAUSTED
    return OutcomeSubreason.SOLVER_UNKNOWN


def _classify_issues(
    issues: Sequence[dict[str, object] | object],
) -> tuple[AnalysisOutcome, OutcomeSubreason]:
    """Classify a non-empty issue collection."""
    target_exception_reason: OutcomeSubreason | None = None

    for issue in issues:
        kind = _issue_kind_name(issue)
        message = _issue_message(issue)
        detector_name = _issue_detector_name(issue)
        reason = _ISSUE_SUBREASONS.get(kind, OutcomeSubreason.UNKNOWN_ISSUE)

        if _issue_is_target_exception(kind, message, detector_name):
            target_exception_reason = _target_exception_subreason(kind, reason)
            continue
        return AnalysisOutcome.ISSUE_FOUND, reason

    return (
        AnalysisOutcome.TARGET_EXCEPTION,
        target_exception_reason or OutcomeSubreason.TARGET_EXCEPTION,
    )


def _issue_is_target_exception(kind: str, message: str, detector_name: str | None) -> bool:
    """Return whether an issue represents escaped target exception propagation."""
    if kind in _TARGET_EXCEPTION_KINDS:
        return True
    if detector_name in _TARGET_EXCEPTION_DETECTOR_NAMES:
        return True
    return message.startswith(_UNHANDLED_EXCEPTION_PREFIX)


def _target_exception_subreason(kind: str, fallback: OutcomeSubreason) -> OutcomeSubreason:
    """Return a target-exception subreason without promoting operation bugs."""
    if kind == "UNHANDLED_EXCEPTION":
        return OutcomeSubreason.TARGET_EXCEPTION
    return fallback


def _issue_kind_name(issue: dict[str, object] | object) -> str:
    """Return the normalized issue-kind enum name from dicts or Issue objects."""
    kind_value = _issue_field(issue, "kind")
    if isinstance(kind_value, str):
        return kind_value
    if kind_value is None:
        return "UNKNOWN"
    name = getattr(kind_value, "name", None)
    return name if isinstance(name, str) else str(kind_value)


def _issue_message(issue: dict[str, object] | object) -> str:
    """Return a normalized issue message."""
    message = _issue_field(issue, "message")
    return message if isinstance(message, str) else ""


def _issue_detector_name(issue: dict[str, object] | object) -> str | None:
    """Return the detector name attached to an issue when available."""
    detector_name = _issue_field(issue, "detector_name")
    return detector_name if isinstance(detector_name, str) else None


def _issue_field(issue: dict[str, object] | object, field_name: str) -> object | None:
    """Read an issue field from serialized dicts or Issue-like objects."""
    if isinstance(issue, dict):
        issue_dict = cast("dict[str, object]", issue)
        return issue_dict.get(field_name)
    return getattr(issue, field_name, None)


def _event_str(event: object, field_name: str) -> str | None:
    """Read a string-ish field from a fallback event."""
    value = getattr(event, field_name, None)
    return value if isinstance(value, str) else None


def _event_value(event: object, field_name: str) -> str:
    """Read an enum/string field from a fallback event as a lowercase value."""
    return _enum_or_string(getattr(event, field_name, "")).lower()


def _enum_or_string(value: object) -> str:
    """Return enum ``value``/``name`` or plain string representation."""
    if isinstance(value, str):
        return value
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, str):
        return enum_value
    enum_name = getattr(value, "name", None)
    if isinstance(enum_name, str):
        return enum_name
    return "" if value is None else str(value)


def _label_for_subreason(subreason: OutcomeSubreason) -> str:
    """Return the stable label for a subreason."""
    return subreason.value
