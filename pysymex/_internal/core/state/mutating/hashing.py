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

"""Structural hash accessors for path-local VM state."""

from __future__ import annotations

from pysymex._internal.core.state.hashing import compute_state_hash_value
from pysymex._internal.core.state.mixin.types import VMStateMixinAttributes


class VMStateHashingMixin(VMStateMixinAttributes):
    """Cache structural summaries used for duplicate-state pruning."""

    def hash_value(self) -> int:
        """Return a cached structural summary used for state deduplication.

        Notes:
            The summary covers selected stacks, stores, constraints,
            exceptions, detector-deferment sites, and loop bookkeeping. It is
            not a semantic-equivalence or path-feasibility proof.

        """
        if self._cached_hash is None:
            self._cached_hash = compute_state_hash_value(self)
        return self._cached_hash
