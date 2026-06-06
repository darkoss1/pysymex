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

"""Scanner value-range pass coordination and degraded-code filtering."""

from __future__ import annotations

import types
from pathlib import Path
from typing import TypeAlias

from pysymex.analysis.domains.ranges.analyzer import ValueRangeChecker
from pysymex.execution.opcodes.common.collections.mapping_protocol import (
    UNSUPPORTED_MAPPING_PROTOCOL,
)
from pysymex.execution.opcodes.common.functions.attribute.fallbacks import (
    UNSUPPORTED_ATTRIBUTE_PROTOCOL,
    UNSUPPORTED_DESCRIPTOR_PROTOCOL,
)
from pysymex.execution.calls.construction_fallbacks import (
    UNSUPPORTED_CONSTRUCTION_PROTOCOL,
)
from pysymex.logger import get_logger
from pysymex.scanner.issue_sink import ScannerIssueSink

logger = get_logger(__name__)

CodeContext: TypeAlias = tuple[types.CodeType, str | None, str | None]

VALUE_RANGE_BLOCKING_DEGRADATIONS = frozenset(
    {
        "unsupported_generator",
        UNSUPPORTED_ATTRIBUTE_PROTOCOL,
        UNSUPPORTED_CONSTRUCTION_PROTOCOL,
        UNSUPPORTED_DESCRIPTOR_PROTOCOL,
        "unsupported_hashed_collection_protocol",
        "unsupported_membership_protocol",
        UNSUPPORTED_MAPPING_PROTOCOL,
        "unsupported_truth_protocol",
    }
)


def emit_value_range_issues(
    *,
    scan_code_with_context: list[CodeContext],
    file_path: Path,
    issue_sink: ScannerIssueSink,
    complete_coverage: dict[int, frozenset[int]] | None = None,
    degraded_by_code: dict[int, frozenset[str]] | None = None,
    suppressed_issue_offsets_by_code: dict[int, frozenset[int]] | None = None,
    suppressed_lines: frozenset[int] | None = None,
) -> None:
    """Emit value-range findings only where VM execution kept sound reachability evidence.

    Limitations:
        Value-range warnings on code segments that degraded during VM execution are
        skipped for degradation markers known to invalidate scanner reachability evidence.
    """
    range_checker = ValueRangeChecker()
    seen_codes: set[int] = set()
    line_suppressions = suppressed_lines or frozenset()
    for code, class_name, full_path in scan_code_with_context:
        if id(code) in seen_codes:
            continue
        seen_codes.add(id(code))
        degraded = (degraded_by_code or {}).get(id(code), frozenset())
        if VALUE_RANGE_BLOCKING_DEGRADATIONS & degraded:
            continue
        try:
            range_warnings = range_checker.check_function(code, str(file_path))
            for warning in range_warnings:
                if warning.line in line_suppressions:
                    continue
                suppressed_offsets = (suppressed_issue_offsets_by_code or {}).get(
                    id(code), frozenset()
                )
                if warning.pc in suppressed_offsets:
                    continue
                covered_offsets = (complete_coverage or {}).get(id(code))
                if covered_offsets is not None and warning.pc not in covered_offsets:
                    continue
                if issue_sink.has_matching_reported_issue(
                    kind=warning.kind,
                    line=warning.line,
                    function_name=code.co_name,
                    class_name=class_name,
                    full_path=full_path,
                ):
                    continue
                issue_sink.handle_issue(
                    {
                        "kind": warning.kind,
                        "message": f"[Value Range] {warning.message}",
                        "line": warning.line,
                        "pc": warning.pc,
                        "function_name": code.co_name,
                        "class_name": class_name,
                        "full_path": full_path,
                        "counterexample": None,
                    }
                )
        except (RuntimeError, TypeError, ValueError):
            logger.debug("Value range analysis failed for %s", code.co_name, exc_info=True)


__all__ = ["VALUE_RANGE_BLOCKING_DEGRADATIONS", "emit_value_range_issues"]
