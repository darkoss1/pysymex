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

"""Detector ``Issue`` reconstruction from spill payloads."""

from __future__ import annotations

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.execution.frontier.spill.detector.fields import (
    issue_kind,
    optional_counterexample,
    optional_int,
    optional_severity,
    optional_str,
    required_bool,
    required_float,
    required_int,
    required_str,
    str_tuple,
)
from pysymex._internal.execution.frontier.spill.detector.types import SpillDetectorDecodeError
from pysymex._internal.execution.frontier.spill.fields.decode import object_payload


def decode_issue(raw_issue: object) -> Issue:
    """Decode one detector issue payload."""
    payload = object_payload(raw_issue)
    if payload is None:
        msg = "detector issue payload is malformed"
        raise SpillDetectorDecodeError(msg)
    return Issue(
        kind=issue_kind(payload, "kind"),
        message=required_str(payload, "message"),
        pc=required_int(payload, "pc"),
        line_number=optional_int(payload, "line_number"),
        function_name=optional_str(payload, "function_name"),
        filename=optional_str(payload, "filename"),
        stack_trace=str_tuple(payload, "stack_trace"),
        class_name=optional_str(payload, "class_name"),
        full_path=optional_str(payload, "full_path"),
        counterexample=optional_counterexample(payload, "counterexample"),
        is_caught=required_bool(payload, "is_caught"),
        confidence=required_float(payload, "confidence"),
        likelihood=required_float(payload, "likelihood"),
        severity=optional_severity(payload, "severity"),
        file=required_str(payload, "file"),
        line=required_int(payload, "line"),
        column=optional_int(payload, "column"),
        explanation=optional_str(payload, "explanation"),
        related_code=optional_str(payload, "related_code"),
        fix_suggestion=optional_str(payload, "fix_suggestion"),
        detector_name=optional_str(payload, "detector_name"),
        suppression_reason=optional_str(payload, "suppression_reason"),
    )
