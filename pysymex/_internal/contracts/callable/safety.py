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

"""Safety checks for callable contract predicates before host execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.contracts.callable.introspection import code_instructions, predicate_code
from pysymex._internal.contracts.callable.policy import HOST_STATE_MUTATION_OPCODES
from pysymex._internal.contracts.callable.stack import reject_unapproved_calls

if TYPE_CHECKING:
    from collections.abc import Callable, Collection


def _reject_host_effects(
    predicate: Callable[..., object],
    *,
    safe_attribute_names: Collection[str] = (),
    safe_value_names: Collection[str] = (),
) -> None:
    """Reject bytecode that can mutate or execute host runtime state."""
    code = predicate_code(predicate)
    if code is None:
        return

    for instruction in code_instructions(code):
        if instruction.opname in HOST_STATE_MUTATION_OPCODES:
            msg = (
                "Callable contract predicates with host-state mutation opcode "
                f"{instruction.opname} are unsupported"
            )
            raise ValueError(
                msg,
            )
    reject_unapproved_calls(
        predicate,
        code,
        safe_attribute_names=frozenset(safe_attribute_names),
        safe_value_names=frozenset(safe_value_names),
    )


class CallableSafety:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    reject_host_effects = staticmethod(_reject_host_effects)
