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

"""Policy constraints for resource lifecycle validation."""

from __future__ import annotations

from pysymex.analysis.domains.resources.lifecycle.operations import ResourceLifecycleOperations
from pysymex.analysis.domains.resources.types import (
    ResourceIssue,
    ResourceIssueKind,
    ResourceKind,
    ResourceState,
)


class ResourceLifecyclePolicy(ResourceLifecycleOperations):
    """Transaction and context-manager resource policies."""

    def check_transaction_state(
        self,
        resource_name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        resource = self._resources.get(resource_name)
        if resource is None or resource.kind != ResourceKind.DATABASE_TRANSACTION:
            return None
        if resource.state != ResourceState.TRANSACTION_ACTIVE:
            return None
        return ResourceIssue(
            kind=ResourceIssueKind.UNCOMMITTED_TRANSACTION,
            message=f"Transaction '{resource_name}' not committed or rolled back",
            resource_kind=resource.kind,
            resource_name=resource_name,
            current_state=resource.state,
            line_number=line_number,
        )
