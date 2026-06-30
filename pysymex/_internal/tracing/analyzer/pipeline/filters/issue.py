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

"""Issue event filters for trace analyzer pipelines."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.analyzer.predicates import TraceEventPredicates

if TYPE_CHECKING:
    from pysymex._internal.tracing.analyzer.pipeline.core import FilterPipeline
    from pysymex._internal.tracing.analyzer.pipeline.criteria import TraceFilterCriteria


def add_issue_filters(pipeline: FilterPipeline, config: TraceFilterCriteria) -> None:
    """Add issue event filters to a filter pipeline.

    Appends filters for severity, detector name, issue kind, message substring,
    Z3 counterexamples, source lines, confidence ranges, and path constraints
    at time of issue.

    Args:
        pipeline: The FilterPipeline instance to add filters to.
        config: Filter criteria for issue events.

    """
    if config.severity:
        sevs: frozenset[str] = frozenset(s.upper() for s in config.severity)
        pipeline.add(
            lambda e, ss=sevs: (TraceEventPredicates.as_str(e.get("severity")) or "").upper() in ss,
        )

    if config.detector:
        det: str = config.detector
        pipeline.add(
            lambda e, s=det: TraceEventPredicates.str_contains(
                TraceEventPredicates.as_str(e.get("detector_name")),
                s,
            ),
        )

    if config.issue_kind:
        ik: str = config.issue_kind
        pipeline.add(
            lambda e, s=ik: TraceEventPredicates.str_contains(
                TraceEventPredicates.as_str(e.get("issue_kind")),
                s,
            ),
        )

    if config.message_contains:
        mc: str = config.message_contains
        pipeline.add(
            lambda e, s=mc: TraceEventPredicates.str_contains(
                TraceEventPredicates.as_str(e.get("message")),
                s,
            ),
        )

    if config.has_z3_model:
        pipeline.add(lambda e: e.get("z3_model") is not None)

    if config.z3_model_var:
        zmv: str = config.z3_model_var
        pipeline.add(lambda e, k=zmv: k in (TraceEventPredicates.as_dict(e.get("z3_model")) or {}))

    if config.issue_source_line is not None:
        isl: int = config.issue_source_line
        pipeline.add(lambda e, s=isl: e.get("source_line") == s)

    if config.confidence:
        conf_lo, conf_hi = config.confidence
        pipeline.add(
            lambda e, lo=conf_lo, hi=conf_hi: TraceEventPredicates.float_field_in_range(
                e,
                "confidence",
                lo,
                hi,
            ),
        )

    if config.constraint_at_issue_contains:
        caic: str = config.constraint_at_issue_contains
        pipeline.add(
            lambda e, s=caic: TraceEventPredicates.constraints_contain(
                TraceEventPredicates.as_list(e.get("constraints_at_issue")),
                s,
            ),
        )
