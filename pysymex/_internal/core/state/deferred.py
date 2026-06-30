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

"""Path-local deferred publication tokens stored on VM states.

The core state layer only needs a hashable publication site and an opaque
payload that can be copied across forks. Execution and detector owners decide
what the payload means and whether it becomes a reported issue.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Hashable


@dataclass(frozen=True, slots=True)
class DeferredStateIssue:
    """Opaque state-carried publication token for upper-layer issue policy.

    Attributes:
        issue: Opaque payload owned by the upper layer that created the token.
        site_key: Hashable site identity included in VM state deduplication.

    """

    issue: object
    site_key: Hashable
