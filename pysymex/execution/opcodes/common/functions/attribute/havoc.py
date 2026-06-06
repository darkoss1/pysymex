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

"""Havoc attribute load helper for common function opcodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types.havoc import HavocValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.functions.attribute.fallbacks import (
    UNMODELED_ATTRIBUTE_HAVOC,
    unmodeled_attribute_havoc_event,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


def load_havoc_attribute(
    state: VMState, obj: HavocValue, attr_name: str, *, push_null: bool
) -> OpcodeResult:
    """Load an attribute from a :class:`~pysymex.core.types.havoc.HavocValue` with caching.

    Side Effects:
        May create fresh havoc cells and type constraints on ``state``.
    """
    havoc_attr_map: dict[str, tuple[HavocValue, z3.BoolRef]] = obj.get_cached_attributes()
    if attr_name in havoc_attr_map:
        havoc_attr, havoc_tc = havoc_attr_map[attr_name]
    else:
        try:
            havoc_attr, havoc_tc = obj.__getattr__(attr_name)
        except AttributeError:
            havoc_attr, havoc_tc = HavocValue.havoc(f"{getattr(obj, '_name')}.{attr_name}")
        havoc_attr_map[attr_name] = (havoc_attr, havoc_tc)

    object_name = str(getattr(obj, "name", getattr(obj, "_name", "havoc")))
    fallback_event = unmodeled_attribute_havoc_event(
        state=state,
        object_name=object_name,
        attr_name=attr_name,
    )

    if push_null:
        state = state.push(obj)
    state = state.push(havoc_attr)
    state = state.add_constraint(havoc_tc)
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNMODELED_ATTRIBUTE_HAVOC],
        fallback_events=[fallback_event],
    )
