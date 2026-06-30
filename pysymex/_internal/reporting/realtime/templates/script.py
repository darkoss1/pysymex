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

"""Assemble browser-side script sections for the realtime visualizer template."""

from __future__ import annotations

from pysymex._internal.reporting.realtime.templates.scripts.core import (
    REALTIME_TEMPLATE_SCRIPT_CORE,
)
from pysymex._internal.reporting.realtime.templates.scripts.panel import (
    REALTIME_TEMPLATE_SCRIPT_PANEL,
)
from pysymex._internal.reporting.realtime.templates.scripts.render import (
    REALTIME_TEMPLATE_SCRIPT_RENDER,
)

REALTIME_TEMPLATE_SCRIPT = (
    REALTIME_TEMPLATE_SCRIPT_CORE + REALTIME_TEMPLATE_SCRIPT_RENDER + REALTIME_TEMPLATE_SCRIPT_PANEL
)
