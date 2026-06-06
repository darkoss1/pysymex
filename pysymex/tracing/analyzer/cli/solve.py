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

"""Solver event arguments for the trace analyzer CLI."""

from __future__ import annotations

import argparse


def add_solve_arguments(parser: argparse.ArgumentParser) -> None:
    """Add CLI arguments for filtering solver events.

    Adds options to filter trace events representing SMT solver telemetry (such as
    solve result, cache hit/miss status, latency bounds, constraint counts, and
    presence of variable names in the model excerpt).

    Args:
        parser: The ArgumentParser instance to which arguments will be added.
    """
    solve_grp = parser.add_argument_group(
        "SolveEvent Filters (event_type=solve)",
        "Filters on SMT solver invocation telemetry events.",
    )
    solve_grp.add_argument(
        "--solve-result",
        type=str,
        default=None,
        choices=["sat", "unsat", "unknown"],
        metavar="RESULT",
        help=(
            "Keep solver events with the given result.  "
            "sat: constraints are satisfiable (feasible path / concrete witness found).  "
            "unsat: constraints are unsatisfiable (path is infeasible).  "
            "unknown: Z3 timed out or could not decide.  "
            "Use --solve-result unknown to find Z3 timeout hotspots."
        ),
    )

    cache_group = solve_grp.add_mutually_exclusive_group()
    cache_group.add_argument(
        "--cache-hit",
        action="store_true",
        default=False,
        help=(
            "Keep solver invocations that were served from the LRU cache "
            "(cache_hit=True).  "
            "A high cache hit rate means the engine is avoiding redundant Z3 "
            "queries.  Use --cache-hit to confirm caching is working."
        ),
    )
    cache_group.add_argument(
        "--cache-miss",
        action="store_true",
        default=False,
        help=(
            "Keep solver invocations that required a real Z3 call "
            "(cache_hit=False).  "
            "Mutually exclusive with --cache-hit.  "
            "Use --cache-miss --solver-latency-min 200 to find expensive "
            "uncached queries that are bottlenecking the engine."
        ),
    )
    solve_grp.add_argument(
        "--solver-latency-min",
        type=float,
        default=None,
        metavar="MS",
        help=(
            "Keep solver events where solver_latency_ms >= MS.  "
            "Use --solver-latency-min 500 to find individual queries that "
            "take more than half a second — these are the primary bottleneck "
            "candidates."
        ),
    )
    solve_grp.add_argument(
        "--solver-latency-max",
        type=float,
        default=None,
        metavar="MS",
        help=(
            "Keep solver events where solver_latency_ms <= MS.  "
            "Useful when combined with --cache-miss to find fast cache misses "
            "(possibly a cache key mis-match bug)."
        ),
    )
    solve_grp.add_argument(
        "--num-constraints-min",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep solver events with at least N constraints in the query.  "
            "Constraint count is a proxy for path depth.  "
            "Use to find the deepest queries."
        ),
    )
    solve_grp.add_argument(
        "--num-constraints-max",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep solver events with at most N constraints in the query.  "
            "Use to study early-path solver behavior."
        ),
    )
    solve_grp.add_argument(
        "--has-model-excerpt",
        action="store_true",
        default=False,
        help=(
            "Keep SAT solver events that include a model_excerpt "
            "(a partial satisfying variable assignment).  "
            "The model excerpt tells you which concrete input values were "
            "inferred by Z3 for a satisfiable path.  "
            "Use this to find the first concrete witness for a bug path."
        ),
    )
    solve_grp.add_argument(
        "--model-var-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep SAT solver events where the model_excerpt dict contains "
            "key NAME.  "
            "Use to find solver calls that inferred a specific concrete value "
            "for a named symbolic variable."
        ),
    )


__all__ = ["add_solve_arguments"]
