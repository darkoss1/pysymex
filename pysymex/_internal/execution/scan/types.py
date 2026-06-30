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

"""Protocols and records for source-file scan execution passes."""

from __future__ import annotations

import types
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.analysis.records import IssueRecord
    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.execution.executors.core import SymbolicExecutor

CodeContext = tuple[types.CodeType, str | None, str | None]


class ScanIssueSink(Protocol):
    """Issue destination used by scan execution orchestration."""

    def handle_issue(self, issue: Issue | IssueRecord) -> None:
        """Record one issue emitted by analysis or execution."""
        ...


class ExecutorTracer(Protocol):
    """Tracing hook that can be installed on a symbolic executor."""

    def install(self, executor: SymbolicExecutor) -> None:
        """Install tracing hooks on *executor*."""
        ...


class ScanExecutionObserver(Protocol):
    """Observer for optional scan execution progress reporting."""

    def activate(self, engine: SymbolicExecutor) -> None:
        """Activate observer hooks on the specified symbolic executor."""
        ...

    def begin_code(self, code: types.CodeType) -> None:
        """Notify the observer that execution has begun for a code object."""
        ...


@dataclass(frozen=True)
class ScanExecutionSetup:
    """Execution-owned executor and configuration for one source-file scan."""

    config: ExecutionConfig
    executor: SymbolicExecutor
