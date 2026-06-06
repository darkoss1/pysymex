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

"""Final concurrency-analysis reporting for the concurrent executor."""

from __future__ import annotations

from pysymex.logger import get_logger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.analysis.domains.concurrency import ConcurrencyAnalyzer
    from pysymex.execution.config.settings import ExecutionConfig

logger = get_logger("pysymex.execution.executors.concurrent")


def finalize_concurrency_analysis(
    concurrency_analyzer: ConcurrencyAnalyzer,
    config: ExecutionConfig,
) -> None:
    """Run final concurrency analysis without executor-level issue conversion.

    Includes DPOR interleaving exploration to find additional data races and
    atomicity violations beyond the single-execution analysis. Prints/logs warnings
    for detected issues.

    Args:
        concurrency_analyzer: The analyzer populated with concurrency events.
        config: The execution configuration containing logging and verbosity options.

    Limitations:
        DPOR exploration is best-effort; failures are logged and do not fail the
        scan unless verbose diagnostics are enabled.
    """
    try:
        all_concurrency_issues = concurrency_analyzer.get_all_issues()
        for ci in all_concurrency_issues:
            logger.warning("[Concurrency] %s", ci.format())
    except (RuntimeError, KeyError, AttributeError) as e:
        if getattr(config, "verbose", False):
            logger.warning("Concurrency finalization error: %s", e)

    try:
        from pysymex.analysis.domains.concurrency.dpor import DPORExplorer

        hb_graph = concurrency_analyzer.hb_graph
        thread_ops = concurrency_analyzer.get_thread_operations()
        if hb_graph and thread_ops and len(thread_ops) > 1:
            explorer = DPORExplorer(hb_graph, thread_ops, max_interleavings=100)
            schedules = explorer.explore()
            race_candidates = explorer.get_race_candidates()
            for op1_id, op2_id in race_candidates:
                op1 = hb_graph.get_operation(op1_id)
                op2 = hb_graph.get_operation(op2_id)
                if op1 and op2:
                    logger.warning(
                        (
                            "[Concurrency] Data race: %s and %s access '%s' "
                            "concurrently (DPOR found %d interleavings)"
                        ),
                        op1.thread_id,
                        op2.thread_id,
                        op1.address,
                        len(schedules),
                    )
            if config.verbose and schedules:
                logger.debug(
                    "  DPOR explored %d interleavings, found %d race candidate(s)",
                    len(schedules),
                    len(race_candidates),
                )
    except (ImportError, RuntimeError, AttributeError) as e:
        if getattr(config, "verbose", False):
            logger.warning("DPOR exploration error: %s", e)
