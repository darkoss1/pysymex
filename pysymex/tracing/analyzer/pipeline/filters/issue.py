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

import argparse

from pysymex.tracing.analyzer.helpers import (
    as_dict,
    as_list,
    as_str,
    constraints_contain,
    float_field_in_range,
    str_contains,
)
from pysymex.tracing.analyzer.pipeline.core import FilterPipeline


def add_issue_filters(pipeline: FilterPipeline, args: argparse.Namespace) -> None:
    """Add issue event filters to a filter pipeline.

    Parses command-line arguments and appends filters to evaluate properties of
    issue events, such as severity level, detector name, issue kind, message substring,
    presence of Z3 counterexamples, variable keys within them, source lines, confidence ranges,
    and path constraints at time of issue.

    Args:
        pipeline: The FilterPipeline instance to add filters to.
        args: Parsed command-line arguments containing filtering criteria.
    """
    if args.severity:
        sevs: frozenset[str] = frozenset(s.upper() for s in args.severity)
        pipeline.add(lambda e, ss=sevs: (as_str(e.get("severity")) or "").upper() in ss)

    if args.detector:
        det: str = args.detector
        pipeline.add(lambda e, s=det: str_contains(as_str(e.get("detector_name")), s))

    if args.issue_kind:
        ik: str = args.issue_kind
        pipeline.add(lambda e, s=ik: str_contains(as_str(e.get("issue_kind")), s))

    if args.message_contains:
        mc: str = args.message_contains
        pipeline.add(lambda e, s=mc: str_contains(as_str(e.get("message")), s))

    if args.has_z3_model:
        pipeline.add(lambda e: e.get("z3_model") is not None)

    if args.z3_model_var:
        zmv: str = args.z3_model_var
        pipeline.add(lambda e, k=zmv: k in (as_dict(e.get("z3_model")) or {}))

    if args.issue_source_line is not None:
        isl: int = args.issue_source_line
        pipeline.add(lambda e, s=isl: e.get("source_line") == s)

    if args.confidence:
        conf_lo, conf_hi = args.confidence
        pipeline.add(
            lambda e, lo=conf_lo, hi=conf_hi: float_field_in_range(
                e,
                "confidence",
                lo,
                hi,
            )
        )

    if args.constraint_at_issue_contains:
        caic: str = args.constraint_at_issue_contains
        pipeline.add(
            lambda e, s=caic: constraints_contain(as_list(e.get("constraints_at_issue")), s)
        )


__all__ = ["add_issue_filters"]
