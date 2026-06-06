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

"""System context filters for trace analyzer pipelines."""

from __future__ import annotations

import argparse

from pysymex.tracing.analyzer.helpers import as_str, str_contains
from pysymex.tracing.analyzer.pipeline.core import FilterPipeline


def add_system_context_filters(pipeline: FilterPipeline, args: argparse.Namespace) -> None:
    """Add system context filters to a filter pipeline.

    Parses command-line arguments and appends filters to check metadata of
    system context events, such as function name substring, source file substring,
    pysymex version, and Z3 version.

    Args:
        pipeline: The FilterPipeline instance to add filters to.
        args: Parsed command-line arguments containing filtering criteria.
    """
    if args.function_name:
        fn_sub: str = args.function_name
        pipeline.add(lambda e, s=fn_sub: str_contains(as_str(e.get("function_name")), s))

    if args.source_file:
        sf_sub: str = args.source_file
        pipeline.add(lambda e, s=sf_sub: str_contains(as_str(e.get("source_file")), s))

    if args.pysymex_version:
        pv: str = args.pysymex_version
        pipeline.add(lambda e, v=pv: e.get("pysymex_version") == v)

    if args.z3_version:
        zv: str = args.z3_version
        pipeline.add(lambda e, v=zv: e.get("z3_version") == v)


__all__ = ["add_system_context_filters"]
