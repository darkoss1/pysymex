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

"""Assemble the HTML/D3 template source for real-time visualization."""

from __future__ import annotations

from pysymex._internal.reporting.realtime.templates.body import REALTIME_TEMPLATE_BODY
from pysymex._internal.reporting.realtime.templates.script import REALTIME_TEMPLATE_SCRIPT
from pysymex._internal.reporting.realtime.templates.styles import REALTIME_TEMPLATE_STYLES

_HTML_PREFIX = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>pysymex — Live Execution Tree</title>
    <meta name="description" content="Real-time symbolic execution tree visualizer for pysymex">
    <script src="https://d3js.org/d3.v7.min.js"></script>
"""

_HTML_AFTER_STYLES = """
</head>
<body>
"""

_HTML_SUFFIX = """
</body>
</html>
"""

HTML_TEMPLATE = (
    _HTML_PREFIX
    + REALTIME_TEMPLATE_STYLES
    + _HTML_AFTER_STYLES
    + REALTIME_TEMPLATE_BODY
    + REALTIME_TEMPLATE_SCRIPT
    + _HTML_SUFFIX
)
