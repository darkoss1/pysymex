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

"""Per-step resource-limit gates for execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.resources.events import HookMap, record_resource_limit_prune
from pysymex._internal.limits.models import LimitExceeded, ResourceType

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.limits.tracker import ResourceTracker


def check_step_depth_limit(
    *,
    session: ExecutionSession,
    resource_tracker: ResourceTracker | None,
    hook_owner: object,
    hooks: HookMap,
    state: VMState,
) -> bool:
    """Return whether a step may execute after applying the depth limit."""
    try:
        if resource_tracker is not None:
            max_depth = resource_tracker.limits.max_depth
            if max_depth is not None and state.depth >= max_depth:
                raise LimitExceeded(
                    ResourceType.DEPTH,
                    state.depth,
                    max_depth,
                )
            resource_tracker.check_depth_limit()
        return True
    except LimitExceeded as exc:
        record_resource_limit_prune(
            session=session,
            exc=exc,
            hook_owner=hook_owner,
            hooks=hooks,
            state=state,
        )
        return False
