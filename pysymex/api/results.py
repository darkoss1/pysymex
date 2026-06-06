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

"""Public result, report, and issue models."""

from __future__ import annotations

from pysymex.analysis.detectors import Issue
from pysymex.analysis.detectors import IssueKind
from pysymex.execution.results.result import ExecutionResult
from pysymex.execution.executors.verified.types import (
    VerifiedExecutionResult,
)
from pysymex.scanner import ScanResult

__all__ = [
    "ExecutionResult",
    "Issue",
    "IssueKind",
    "ScanResult",
    "VerifiedExecutionResult",
]
