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

"""Manage SARIF rules and CWE identifiers.

Aggregates descriptors from security and reliability rule sets, providing a mapper
function to resolve dynamic vulnerability names into static rule IDs.
"""

from __future__ import annotations

from pysymex._internal.reporting.sarif.rules.reliability import SECURITY_RULES_RELIABILITY
from pysymex._internal.reporting.sarif.rules.security import SECURITY_RULES_SECURITY

SECURITY_RULES = SECURITY_RULES_SECURITY | SECURITY_RULES_RELIABILITY


def vuln_type_to_rule_id(vuln_type: str) -> str:
    """Map a dynamic vulnerability type string to a stable SARIF rule identifier.

    This ensures that findings are grouped under the correct CWE-mapped rule
    in security dashboards. Defaults to SVM999 for unknown issue types.
    """
    v = str(vuln_type).lower().replace(" ", "_")
    mapping = {
        "server_side_request_forgery_(ssrf)": "SVM004",
        "insecure_deserialization": "SVM005",
        "potentially_unsafe_deserialization": "SVM005",
        "server_side_template_injection": "SVM006",
        "hardcoded_secret": "SVM007",
        "weak_cryptography": "SVM008",
        "division_by_zero": "SVM010",
        "assertion_error": "SVM011",
        "index_error": "SVM012",
        "unused_variable": "SVM013",
        "key_error": "SVM014",
    }
    return mapping.get(v, "SVM999")
