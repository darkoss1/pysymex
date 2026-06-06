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

"""Frontier runtime rollout modes.

These modes make POLAR/CEGIS rollout state explicit. They do not grant the
frontier or scheduler authority over solver truth, detector confidence, or
work removal.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["FrontierRuntimeMode"]


class FrontierRuntimeMode(Enum):
    """Supported rollout states for the execution frontier."""

    POLAR_CEGIS_SHADOW = "polar_cegis_shadow"
    POLAR_CEGIS_RUNTIME = "polar_cegis_runtime"

    @property
    def shadow_telemetry_enabled(self) -> bool:
        """Return whether this mode should emit POLAR/CEGIS shadow diagnostics."""
        return True

    @property
    def certificate_pruning_enabled(self) -> bool:
        """Return whether exact owner certificates may prune queued work."""
        return self is FrontierRuntimeMode.POLAR_CEGIS_RUNTIME

    @property
    def compact_queueing_enabled(self) -> bool:
        """Return whether admission should replace live states with checkpoints."""
        return False

    @property
    def runtime_replacement_enabled(self) -> bool:
        """Compatibility alias for the current certificate-pruning rollout gate."""
        return self.certificate_pruning_enabled
