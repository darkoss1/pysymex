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

"""Lock-specific resource lifecycle state machine and checks."""

from __future__ import annotations

from pysymex.analysis.domains.resources.lifecycle.checker import ResourceLifecycleChecker
from pysymex.analysis.domains.resources.lifecycle.tracked import TrackedResource
from pysymex.analysis.domains.resources.types import ResourceIssue, ResourceIssueKind, ResourceKind


class LockResourceChecker(ResourceLifecycleChecker):
    """Specialized checker for lock resources."""

    def __init__(self, timeout_ms: int = 5000) -> None:
        super().__init__(timeout_ms)
        self.lock_order: list[str] = []
        self.held_locks: set[str] = set()

    def create_lock(
        self,
        name: str,
        line_number: int | None = None,
    ) -> TrackedResource:
        return self.create_resource(name, ResourceKind.LOCK, line_number)

    def acquire_lock(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        if name in self.held_locks:
            return ResourceIssue(
                kind=ResourceIssueKind.DOUBLE_ACQUIRE,
                message=f"Lock '{name}' already held by this thread",
                resource_name=name,
                line_number=line_number,
            )
        issue = self.check_action(name, "acquire", line_number)
        if issue is None:
            self.held_locks.add(name)
        return issue

    def release_lock(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        if name not in self.held_locks:
            return ResourceIssue(
                kind=ResourceIssueKind.DOUBLE_RELEASE,
                message=f"Lock '{name}' not held",
                resource_name=name,
                line_number=line_number,
            )
        issue = self.check_action(name, "release", line_number)
        if issue is None:
            self.held_locks.discard(name)
        return issue

    def set_lock_order(self, order: list[str]) -> None:
        self.lock_order = order

    def check_current_lock_order(
        self,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        if not self.lock_order:
            return None
        return self.check_lock_ordering(list(self.held_locks), self.lock_order, line_number)
