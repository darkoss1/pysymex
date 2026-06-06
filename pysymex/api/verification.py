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

"""Public verification entry points."""

from __future__ import annotations

from pysymex.execution.executors.verified.api import check_arithmetic
from pysymex.execution.executors.verified.api import check_contracts
from pysymex.execution.executors.verified.api import prove_termination
from pysymex.execution.executors.verified.api import verify
from pysymex.execution.executors.verified.executor import VerifiedExecutor
from pysymex.execution.executors.verified.types import (
    VerifiedExecutionConfig,
)
from pysymex.execution.executors.verified.types import (
    VerifiedExecutionResult,
)

__all__ = [
    "VerifiedExecutionConfig",
    "VerifiedExecutionResult",
    "VerifiedExecutor",
    "check_arithmetic",
    "check_contracts",
    "prove_termination",
    "verify",
]
