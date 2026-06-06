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

"""Facade for VM-facing contract runtime hooks."""

from __future__ import annotations

from pysymex.contracts.runtime.calls import inject_call_preconditions
from pysymex.contracts.runtime.diagnostics import (
    issue_severity_for_clause,
    record_diagnostic_issue,
)
from pysymex.contracts.runtime.entry import inject_preconditions_initial
from pysymex.contracts.runtime.returns import inject_postconditions

__all__ = [
    "inject_call_preconditions",
    "inject_postconditions",
    "inject_preconditions_initial",
    "issue_severity_for_clause",
    "record_diagnostic_issue",
]
