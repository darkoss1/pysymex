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

"""Stable VM state mutation mixin assembled from focused method families."""

from __future__ import annotations

from pysymex._internal.core.state.mutating.bindings import VMStateBindingMixin
from pysymex._internal.core.state.mutating.frames import VMStateFrameMixin
from pysymex._internal.core.state.mutating.hashing import VMStateHashingMixin
from pysymex._internal.core.state.mutating.path import VMStatePathMixin
from pysymex._internal.core.state.mutating.stack import VMStateStackMixin


class VMStateMutationMixin(
    VMStateStackMixin,
    VMStateBindingMixin,
    VMStatePathMixin,
    VMStateFrameMixin,
    VMStateHashingMixin,
):
    """Mutate one execution path's stacks, stores, and constraints in place.

    The focused parent mixins own the individual mutation families. This class
    preserves the stable method surface consumed by :class:`VMState` while
    keeping state-transition responsibilities split by concern.

    Notes:
        Helpers that mutate fields included in :meth:`hash_value` clear the
        cached structural summary so duplicate-state pruning cannot compare
        stale stack, store, frame, or block metadata.

    """
