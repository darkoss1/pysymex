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

"""Secondary resource lifecycle checks (e.g. double-close, use-after-close)."""

from __future__ import annotations

from pysymex.analysis.domains.resources.lifecycle.core import ResourceLifecycleCore
from pysymex.analysis.domains.resources.types import (
    ResourceIssue,
    ResourceIssueKind,
    ResourceState,
)


class ResourceLifecycleOperations(ResourceLifecycleCore):
    """Use-after, double-operation, lock-order, and transaction checks."""

    def check_use_after(
        self,
        resource_name: str,
        action: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        resource = self._resources.get(resource_name)
        if resource is None:
            return None
        dead_states = {
            ResourceState.CLOSED,
            ResourceState.FILE_CLOSED,
            ResourceState.FREED,
            ResourceState.RELEASED,
            ResourceState.DISCONNECTED,
        }
        if resource.state not in dead_states:
            return None
        if resource.state in {ResourceState.CLOSED, ResourceState.FILE_CLOSED}:
            kind = ResourceIssueKind.USE_AFTER_CLOSE
        elif resource.state == ResourceState.FREED:
            kind = ResourceIssueKind.USE_AFTER_FREE
        elif resource.state == ResourceState.DISCONNECTED:
            kind = ResourceIssueKind.USE_AFTER_DISCONNECT
        else:
            kind = ResourceIssueKind.USE_AFTER_RELEASE
        return ResourceIssue(
            kind=kind,
            message=f"Using '{resource_name}' after {resource.state.name}",
            resource_kind=resource.kind,
            resource_name=resource_name,
            current_state=resource.state,
            line_number=line_number,
        )

    def check_double_operation(
        self,
        resource_name: str,
        action: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        resource = self._resources.get(resource_name)
        if resource is None:
            return None
        if action in {"close", "free", "release", "disconnect"}:
            issue = self._check_dead_state_operation(resource_name, action, line_number)
            if issue is not None:
                return issue
        if action in {"acquire", "lock"} and resource.state == ResourceState.LOCK_LOCKED:
            return ResourceIssue(
                kind=ResourceIssueKind.DOUBLE_ACQUIRE,
                message=f"Acquiring already held lock '{resource_name}'",
                resource_kind=resource.kind,
                resource_name=resource_name,
                current_state=resource.state,
                line_number=line_number,
            )
        return None

    def _check_dead_state_operation(
        self,
        resource_name: str,
        action: str,
        line_number: int | None,
    ) -> ResourceIssue | None:
        resource = self._resources[resource_name]
        dead_states = {
            ResourceState.CLOSED,
            ResourceState.FILE_CLOSED,
            ResourceState.FREED,
            ResourceState.RELEASED,
            ResourceState.LOCK_UNLOCKED,
            ResourceState.DISCONNECTED,
        }
        if resource.state not in dead_states:
            return None
        if action == "close":
            kind = ResourceIssueKind.DOUBLE_CLOSE
        elif action == "free":
            kind = ResourceIssueKind.DOUBLE_FREE
        elif action == "release":
            kind = ResourceIssueKind.DOUBLE_RELEASE
        elif action == "disconnect":
            kind = ResourceIssueKind.DOUBLE_DISCONNECT
        else:
            kind = ResourceIssueKind.DOUBLE_CLOSE
        return ResourceIssue(
            kind=kind,
            message=f"Double {action} on '{resource_name}'",
            resource_kind=resource.kind,
            resource_name=resource_name,
            current_state=resource.state,
            line_number=line_number,
        )

    def check_lock_ordering(
        self,
        locks: list[str],
        expected_order: list[str],
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        actual_order: list[str] = []
        for lock_name in locks:
            resource = self._resources.get(lock_name)
            if resource is None:
                continue
            for action, _state, _ in resource.history:
                if action == "acquire" and lock_name not in actual_order:
                    actual_order.append(lock_name)
        return self._find_lock_order_violation(actual_order, expected_order, line_number)

    def _find_lock_order_violation(
        self,
        actual_order: list[str],
        expected_order: list[str],
        line_number: int | None,
    ) -> ResourceIssue | None:
        for i, lock in enumerate(actual_order):
            if lock not in expected_order:
                continue
            expected_idx = expected_order.index(lock)
            for prev_lock in actual_order[:i]:
                if prev_lock in expected_order and expected_order.index(prev_lock) > expected_idx:
                    return ResourceIssue(
                        kind=ResourceIssueKind.LOCK_ORDER_VIOLATION,
                        message=f"Lock order violation: {prev_lock} acquired before {lock}",
                        resource_name=lock,
                        line_number=line_number,
                    )
        return None
