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

"""SARIF generation logic for pysymex."""

from __future__ import annotations

from pysymex.reporting.sarif.generator import (
    SARIFGenerator,
    generate_sarif,
)
from pysymex.reporting.sarif.results import (
    issue_to_sarif_result,
    vulnerability_to_sarif_result,
)
from pysymex.reporting.sarif.rules import (
    SECURITY_RULES,
    vuln_type_to_rule_id,
)
from pysymex.reporting.sarif.severity import (
    severity_to_level,
    severity_to_security_severity,
)

__all__ = [
    "SARIFGenerator",
    "SECURITY_RULES",
    "generate_sarif",
    "issue_to_sarif_result",
    "severity_to_level",
    "severity_to_security_severity",
    "vulnerability_to_sarif_result",
    "vuln_type_to_rule_id",
]
