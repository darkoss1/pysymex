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

"""Class invariant obligation policy and runtime checks."""

from __future__ import annotations

from pysymex.contracts.invariants.checks import check_class_invariants
from pysymex.contracts.invariants.policy import (
    DEFAULT_INVARIANT_POLICY,
    InvariantCheckPoint,
    InvariantPolicy,
)
from pysymex.contracts.invariants.targets import (
    class_invariants_for_callable,
    has_invariant_exit_obligations,
    invariant_obligation_count_for_callable,
    invariant_target_for_callable,
)

__all__ = [
    "DEFAULT_INVARIANT_POLICY",
    "InvariantCheckPoint",
    "InvariantPolicy",
    "check_class_invariants",
    "class_invariants_for_callable",
    "has_invariant_exit_obligations",
    "invariant_obligation_count_for_callable",
    "invariant_target_for_callable",
]
