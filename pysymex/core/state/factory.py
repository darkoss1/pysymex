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

"""Construct root execution states without owning VMState behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.state.record import VMState

if TYPE_CHECKING:
    from pysymex.typing import StackValue


def create_initial_state(
    local_vars: dict[str, StackValue] | None = None,
    global_vars: dict[str, StackValue] | None = None,
    constraints: list[z3.BoolRef] | None = None,
) -> VMState:
    """Create a root VM state with a default ``__name__`` global binding.

    Args:
        local_vars: Initial local variables.
        global_vars: Initial global variables.
        constraints: Initial path constraints.

    Returns:
        A fresh root state with the supplied constraints stored but not solved.

    Side Effects:
        When a non-empty ``global_vars`` dictionary lacks ``"__name__"``,
        adds the default binding to that supplied dictionary.
    """
    gvars = global_vars or {}
    if "__name__" not in gvars:
        gvars["__name__"] = "__main__"

    return VMState(
        stack=[],
        local_vars=local_vars or {},
        global_vars=gvars,
        path_constraints=constraints or [],
        pc=0,
    )


__all__ = ["create_initial_state"]
