# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Exception analysis package — exception tracking and handler analysis.

Submodules
----------
analysis  Exception type inference and warning generation
handler   Exception handler detection and skip-issue logic
"""

from __future__ import annotations

from pysymex.analysis.exceptions.analysis import (
    ExceptionAnalyzer,
    ExceptionWarningKind,
)
from pysymex.analysis.exceptions.handler import (
    ExceptionHandlerAnalyzer,
    ExceptionHandlerInfo,
    ExceptionHandlerType,
    should_skip_issue_in_handler,
)

__all__ = [
    "ExceptionAnalyzer",
    "ExceptionHandlerAnalyzer",
    "ExceptionHandlerInfo",
    "ExceptionHandlerType",
    "ExceptionWarningKind",
    "should_skip_issue_in_handler",
]
