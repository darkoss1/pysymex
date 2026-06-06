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

Part of the reporting and analysis layer. Normalizes issues emitted by
symbolic execution or scanner analysis passes, filtering out duplicates
and implementing counterexample-dominance logic before appending to the final scan results.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.analysis.detectors import Issue
from pysymex.analysis.detectors.protocols import ScanReporter
from pysymex.analysis.scan.records import normalize_trigger_input
from pysymex.config import is_object_dict
from pysymex.scanner.types import IssueRecord, ScanResult


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

        if is_object_dict(issue):
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
        issue_has_trigger = _has_counterexample(issue)
        if issue_has_trigger:
            existing_trigger = False
            retained: list[IssueRecord] = []
            for existing in self.result.issues:
                if _issue_site_key(existing) != site_key:
                    retained.append(existing)
                    continue
                if _has_counterexample(existing):
                    existing_trigger = True
                    retained.append(existing)
            self.result.issues = retained
            return existing_trigger

        for existing in self.result.issues:
            if _issue_site_key(existing) == site_key and _has_counterexample(existing):
                return True
        return False

    def has_matching_reported_issue(
        self,
        *,
        kind: str,
        line: int | None,
        function_name: str,
        class_name: str | None,
        full_path: str | None,
    ) -> bool:
        """Check if a matching issue has already been reported to the sink.

        Args:
            kind: The kind of the issue (e.g. ``"DIVISION_BY_ZERO"``).
            line: The line number of the issue.
            function_name: The function name where the issue occurred.
            class_name: The class name where the issue occurred, or ``None``.
            full_path: The full path of the source file, or ``None``.

        Returns:
            ``True`` if an identical issue has already been reported, ``False`` otherwise.
        """
        for existing in self.result.issues:
            if str(existing.get("kind")) != kind:
                continue
            if existing.get("line") != line:
                continue
            if existing.get("function_name") != function_name:
                continue
            if existing.get("class_name") != class_name:
                continue
            if existing.get("full_path") != full_path:
                continue
            return True
        return False
