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

"""Internal structural protocol for concurrency analyzer helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from pysymex.analysis.domains.concurrency.happens_before import HappensBeforeGraph
from pysymex.analysis.domains.concurrency.models import ConcurrencyIssue, Thread

if TYPE_CHECKING:
    from pysymex.core.solver.engine.incremental import IncrementalSolver


class ConcurrencyAnalyzerState(Protocol):
    """Protocol defining the attributes and state required by concurrency helper functions."""

    timeout_ms: int
    solver: IncrementalSolver
    threads: dict[str, Thread]
    shared_variables: set[str]
    locks: dict[str, str | None]
    lock_acquisitions: dict[str, list[str]]
    hb_graph: HappensBeforeGraph
    thread_op_ids: dict[str, list[int]]
    issues: list[ConcurrencyIssue]
    has_lock_activity: bool


__all__ = ["ConcurrencyAnalyzerState"]
