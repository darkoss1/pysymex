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

"""File-handle-specific resource lifecycle state machine and checks."""

from __future__ import annotations

from pysymex.analysis.domains.resources.lifecycle.checker import ResourceLifecycleChecker
from pysymex.analysis.domains.resources.lifecycle.tracked import TrackedResource
from pysymex.analysis.domains.resources.types import ResourceIssue, ResourceKind


class FileResourceChecker(ResourceLifecycleChecker):
    """Specialized checker for file resources."""

    def open_file(
        self,
        name: str,
        mode: str = "r",
        line_number: int | None = None,
    ) -> tuple[TrackedResource, ResourceIssue | None]:
        resource = self.create_resource(name, ResourceKind.FILE, line_number)
        if "w" in mode:
            action = "open_write"
        elif "a" in mode:
            action = "open_append"
        elif "+" in mode:
            action = "open_readwrite"
        else:
            action = "open_read"
        issue = self.check_action(name, action, line_number)
        return (resource, issue)

    def read_file(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        issue = self.check_use_after(name, "read", line_number)
        if issue:
            return issue
        return self.check_action(name, "read", line_number)

    def write_file(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        issue = self.check_use_after(name, "write", line_number)
        if issue:
            return issue
        return self.check_action(name, "write", line_number)

    def close_file(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        issue = self.check_double_operation(name, "close", line_number)
        if issue:
            return issue
        return self.check_action(name, "close", line_number)
