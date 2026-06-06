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

"""Runtime contract hooks and evidence capture.

This package owns the VM-facing contract integration layer. It receives
execution state from the engine, creates path-local obligations, records
evidence, and returns detector issues for the current path. It does not own
decorator metadata, predicate compilation, solver implementation, or verified
report formatting.
"""

from __future__ import annotations

from pysymex.contracts.runtime.calls import inject_call_preconditions
from pysymex.contracts.runtime.capture import (
    RuntimeContractOutcome,
    capture_runtime_contract_outcomes,
    record_runtime_contract_evidence,
    record_runtime_contract_outcome,
)
from pysymex.contracts.runtime.entry import inject_preconditions_initial
from pysymex.contracts.runtime.returns import inject_postconditions

__all__ = [
    "RuntimeContractOutcome",
    "capture_runtime_contract_outcomes",
    "inject_call_preconditions",
    "inject_postconditions",
    "inject_preconditions_initial",
    "record_runtime_contract_evidence",
    "record_runtime_contract_outcome",
]
