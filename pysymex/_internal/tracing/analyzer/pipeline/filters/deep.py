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

"""Deep-search trace analyzer filters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.analyzer.predicates import TraceEventPredicates

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.tracing.analyzer.pipeline.core import FilterPipeline
    from pysymex._internal.tracing.analyzer.pipeline.criteria import TraceFilterCriteria


def add_deep_filters(pipeline: FilterPipeline, config: TraceFilterCriteria) -> None:
    """Append filters that search across multiple nested event fields."""
    if config.touches_var:
        tv: str = config.touches_var

        def _touches_var(e: Mapping[str, object], needle: str = tv) -> bool:
            """Touches var."""
            for item in TraceEventPredicates.as_list(e.get("stack")) or []:
                if needle in str(item):
                    return True
            for mapping_key in (
                "local_vars",
                "global_vars",
                "mem_diff",
                "model_excerpt",
                "z3_model",
                "initial_symbolic_args",
            ):
                mapping = TraceEventPredicates.as_dict(e.get(mapping_key)) or {}
                for k, v in mapping.items():
                    if needle in str(k) or needle in str(v):
                        return True
            return False

        pipeline.add(_touches_var)

    if config.constraint_contains:
        cc: str = config.constraint_contains

        def _any_constraint(e: Mapping[str, object], needle: str = cc) -> bool:
            """Any constraint."""
            ca = TraceEventPredicates.as_dict(e.get("constraint_added"))
            if ca and needle in (TraceEventPredicates.as_str(ca.get("smtlib")) or ""):
                return True

            if TraceEventPredicates.constraints_contain(
                TraceEventPredicates.as_list(e.get("path_constraints")),
                needle,
            ):
                return True

            if TraceEventPredicates.constraints_contain(
                TraceEventPredicates.as_list(e.get("constraint_excerpt")),
                needle,
            ):
                return True

            if TraceEventPredicates.constraints_contain(
                TraceEventPredicates.as_list(e.get("query_constraint_excerpt")),
                needle,
            ):
                return True

            return bool(
                TraceEventPredicates.constraints_contain(
                    TraceEventPredicates.as_list(e.get("constraints_at_issue")),
                    needle,
                ),
            )

        pipeline.add(_any_constraint)

    if config.any_field_contains:
        _ = config.any_field_contains
