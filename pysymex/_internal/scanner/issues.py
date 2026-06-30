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

"""Scanner issue normalization and deduplication.

Owns the final scan-result issue sink. It accepts issues emitted by analysis
and execution owners, normalizes them into scanner records, filters duplicates,
and applies counterexample-dominance before appending to the final result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.analysis.records import IssueRecord, normalize_trigger_input
from pysymex._internal.guards import RuntimeObjectGuards

if TYPE_CHECKING:
    from pysymex._internal.scanner.protocols import ScanReporter
    from pysymex._internal.scanner.types import ScanResult


def _has_counterexample(issue: IssueRecord) -> bool:
    """Return True when an issue carries concrete trigger data."""
    return normalize_trigger_input(issue.get("counterexample")) is not None


def _issue_site_key(issue: IssueRecord) -> tuple[str, object, object, object, object]:
    """Return the same-site key used to rank scanner issue variants."""
    return (
        str(issue.get("kind", "UNKNOWN")),
        issue.get("line"),
        issue.get("function_name"),
        issue.get("class_name"),
        issue.get("full_path"),
    )


def _issue_source_operation_key(issue: IssueRecord) -> tuple[str, object, object] | None:
    """Return a source-operation key when line and column attribution are precise."""
    line = issue.get("line")
    column = issue.get("column")
    if not isinstance(line, int) or not isinstance(column, int):
        return None
    return (str(issue.get("kind", "UNKNOWN")), line, column)


def _issue_pc_key(issue: IssueRecord) -> tuple[str, object, object, object, object]:
    """Return a bytecode-site key used when line attribution is less precise."""
    return (
        str(issue.get("kind", "UNKNOWN")),
        issue.get("pc"),
        issue.get("function_name"),
        issue.get("class_name"),
        issue.get("full_path"),
    )


def _issue_message_key(issue: IssueRecord) -> tuple[str, object, object, object, object]:
    """Return a same-message key used to rank helper-site issue variants."""
    return (
        str(issue.get("kind", "UNKNOWN")),
        issue.get("message"),
        issue.get("function_name"),
        issue.get("class_name"),
        issue.get("full_path"),
    )


def _issue_line_message_key(issue: IssueRecord) -> tuple[str, object, object]:
    """Return a line/message key used to prefer precise source columns."""
    return (
        str(issue.get("kind", "UNKNOWN")),
        issue.get("line"),
        issue.get("message"),
    )


def _has_precise_column(issue: IssueRecord) -> bool:
    """Return whether an issue record carries a source column."""
    return isinstance(issue.get("column"), int)


def _name_family_signature(issue: IssueRecord) -> tuple[str, str] | None:
    """Return exception/name identity for name-family reports when parseable."""
    kind = str(issue.get("kind", "UNKNOWN"))
    message = str(issue.get("message", ""))
    if kind == "UNBOUND_VARIABLE":
        name = _quoted_name_after_prefix(message, "Variable ")
        return ("UnboundLocalError", name) if name is not None else None
    if kind == "NAME_ERROR":
        name = _quoted_name_after_prefix(message, "Variable ")
        return ("NameError", name) if name is not None else None
    if kind != "UNHANDLED_EXCEPTION":
        return None
    if not message.startswith("Path raises unhandled exception: "):
        return None
    if message.startswith("Path raises unhandled exception: UnboundLocalError: "):
        name = _quoted_name_after_prefix(message, "local variable ")
        return ("UnboundLocalError", name) if name is not None else None
    if message.startswith("Path raises unhandled exception: NameError: "):
        name = _quoted_name_after_prefix(message, "name ")
        return ("NameError", name) if name is not None else None
    return None


def _quoted_name_after_prefix(message: str, prefix: str) -> str | None:
    """Return a quoted identifier following *prefix* in an issue message."""
    match = re.search(rf"{re.escape(prefix)}'([^']+)'", message)
    if match is None:
        return None
    return match.group(1)


def _issue_exact_key(issue: IssueRecord) -> tuple[str, object, object, object, object, object]:
    """Return the exact finding key used to collapse repeated trigger-backed issues."""
    return (
        str(issue.get("kind", "UNKNOWN")),
        issue.get("message"),
        issue.get("line"),
        issue.get("pc"),
        issue.get("function_name"),
        issue.get("full_path"),
    )


@dataclass
class ScannerIssueSink:
    """Processes, deduplicates, and filters issues found during target scanning.

    Coordinates issue reporting by converting different issue representations,
    suppressing blocked attribute errors at specific resolution sites, and ensuring
    only unique issues (optionally ranked by trigger-backed dominance) are preserved.

    Attributes:
        result: The scanner result container where issues are accumulated.
        blocked_resolution_sites: Locations where attribute errors should be suppressed.
        dedup_enabled: Whether to enable issue deduplication.
        reporter: Optional reporter to notify on new issues.
        verbose: Whether to output verbose notifications.
        seen: Cache of seen issue signature strings.

    """

    result: ScanResult
    blocked_resolution_sites: set[tuple[int, str | None, str | None, str | None]]
    dedup_enabled: bool
    reporter: ScanReporter | None = None
    verbose: bool = False
    seen: set[str] = field(default_factory=set[str])

    def handle_issue(self, issue: Issue | IssueRecord) -> None:
        """Process and deduplicate a detected issue for reporting.

        Converts the incoming issue to a canonical dict record format, filters it
        against active suppression sites, and registers it in the result list if not
        duplicate.

        Args:
            issue: The issue object or record dictionary to process.

        Side Effects:
            Mutates ``result.issues`` and the ``seen`` set. Invokes the ``reporter``
            callback when verbose reporting is enabled.

        """
        issue_dict: IssueRecord

        if RuntimeObjectGuards.dict(issue):
            issue_dict = {}
            for key_obj, value_obj in issue.items():
                issue_dict[str(key_obj)] = value_obj
            raw_kind = str(issue_dict.get("kind", "UNKNOWN"))
            raw_line = issue_dict.get("line", "?")
            raw_pc = issue_dict.get("pc", 0)
        elif isinstance(issue, Issue):
            issue_obj = issue
            raw_kind = issue_obj.kind.name
            raw_line = issue_obj.line_number
            raw_pc = issue_obj.pc
            counterexample = normalize_trigger_input(issue_obj.get_counterexample())
            issue_dict = {
                "kind": raw_kind,
                "message": issue_obj.message,
                "line": raw_line,
                "pc": raw_pc,
                "function_name": issue_obj.function_name,
                "class_name": getattr(issue_obj, "class_name", None),
                "full_path": getattr(issue_obj, "full_path", None),
                "column": issue_obj.column,
                "counterexample": counterexample,
                "confidence": issue_obj.confidence,
                "likelihood": issue_obj.likelihood,
                "suppression_reason": issue_obj.suppression_reason,
            }
        else:
            return
        issue_dict["counterexample"] = normalize_trigger_input(issue_dict.get("counterexample"))

        raw_function_name = issue_dict.get("function_name")
        raw_class_name = issue_dict.get("class_name")
        raw_full_path = issue_dict.get("full_path")
        if (
            raw_kind == "ATTRIBUTE_ERROR"
            and isinstance(raw_line, int)
            and (
                raw_line,
                str(raw_function_name) if raw_function_name is not None else None,
                str(raw_class_name) if raw_class_name is not None else None,
                str(raw_full_path) if raw_full_path is not None else None,
            )
            in self.blocked_resolution_sites
        ):
            return

        msg_key = (
            f"[{raw_kind}] @ {raw_line}:{raw_pc}:"
            f"{raw_function_name}:{raw_class_name}:{raw_full_path}"
        )

        if self.dedup_enabled:
            issue_has_trigger = _has_counterexample(issue_dict)
            if msg_key in self.seen and not issue_has_trigger:
                return
            if self._apply_same_site_counterexample_dominance(issue_dict):
                return
            self.seen.add(msg_key)

        self.result.issues.append(issue_dict)
        if self.verbose and self.reporter:
            self.reporter.on_issue(issue_dict)

    def _apply_same_site_counterexample_dominance(self, issue: IssueRecord) -> bool:
        """Drop same-site non-trigger variants once trigger-backed evidence exists.

        If the incoming issue carries a counterexample, removes any existing issues
        at the same code location that lack a counterexample. If the incoming issue
        lacks a counterexample and one already exists at this location with a
        counterexample, the new issue is discarded.

        Args:
            issue: The incoming issue record to check for dominance.

        Returns:
            ``True`` if the incoming issue is dominated by an existing issue and should
            be discarded, ``False`` if it should be retained.

        Side Effects:
            Mutates ``self.result.issues`` to remove dominated issues.

        """
        site_key = _issue_site_key(issue)
        source_operation_key = _issue_source_operation_key(issue)
        issue_has_trigger = _has_counterexample(issue)
        pc_key = _issue_pc_key(issue)
        message_key = _issue_message_key(issue)
        line_message_key = _issue_line_message_key(issue)
        exact_key = _issue_exact_key(issue)
        issue_has_column = _has_precise_column(issue)
        name_family_signature = _name_family_signature(issue)
        name_family_is_specialized = str(issue.get("kind", "UNKNOWN")) in {
            "NAME_ERROR",
            "UNBOUND_VARIABLE",
        }
        if name_family_signature is not None:
            retained_name_family: list[IssueRecord] = []
            for existing in self.result.issues:
                if _name_family_signature(existing) != name_family_signature:
                    retained_name_family.append(existing)
                    continue
                existing_is_specialized = str(existing.get("kind", "UNKNOWN")) in {
                    "NAME_ERROR",
                    "UNBOUND_VARIABLE",
                }
                if not name_family_is_specialized and existing_is_specialized:
                    return True
                if name_family_is_specialized and not existing_is_specialized:
                    continue
                retained_name_family.append(existing)
            if len(retained_name_family) != len(self.result.issues):
                self.result.issues = retained_name_family
        if issue_has_trigger:
            existing_trigger = False
            retained: list[IssueRecord] = []
            for existing in self.result.issues:
                if (
                    _issue_site_key(existing) != site_key
                    and _issue_pc_key(existing) != pc_key
                    and _issue_message_key(existing) != message_key
                    and (
                        source_operation_key is None
                        or _issue_source_operation_key(existing) != source_operation_key
                    )
                ):
                    retained.append(existing)
                    continue
                if _has_counterexample(existing):
                    if _issue_exact_key(existing) == exact_key or (
                        source_operation_key is not None
                        and _issue_source_operation_key(existing) == source_operation_key
                        and _issue_site_key(existing) == site_key
                    ):
                        existing_trigger = True
                    retained.append(existing)
            self.result.issues = retained
            return existing_trigger

        retained = []
        found_precise_line_message = False
        for existing in self.result.issues:
            same_line_message = _issue_line_message_key(existing) == line_message_key
            if same_line_message and _has_precise_column(existing) and not issue_has_column:
                return True
            if same_line_message and issue_has_column and not _has_precise_column(existing):
                continue
            retained.append(existing)
            if (
                same_line_message
                and _has_precise_column(existing)
                and _issue_site_key(existing) == site_key
            ):
                found_precise_line_message = True
        if len(retained) != len(self.result.issues):
            self.result.issues = retained
        if found_precise_line_message and issue_has_column:
            return True

        for existing in self.result.issues:
            if (
                _issue_site_key(existing) == site_key
                or _issue_pc_key(existing) == pc_key
                or _issue_message_key(existing) == message_key
                or (
                    source_operation_key is not None
                    and _issue_source_operation_key(existing) == source_operation_key
                )
            ) and _has_counterexample(existing):
                return True
        return False
