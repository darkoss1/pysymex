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

"""Declare SARIF rule descriptors for reliability and runtime faults.

Provides rule definitions including descriptions and CWE mappings for division
by zero, assertion errors, and related reliability issues.
"""

from __future__ import annotations

from pysymex.reporting.sarif.types import ReportingDescriptor

SECURITY_RULES_RELIABILITY: dict[str, ReportingDescriptor] = {
    "SVM008": ReportingDescriptor(
        id="SVM008",
        name="WeakCryptography",
        short_description="Weak cryptographic algorithm detected",
        full_description=(
            "A weak or deprecated cryptographic algorithm is being used, "
            "which may not provide adequate security."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/327.html",
        default_level="warning",
        properties={
            "security-severity": "5.9",
            "tags": ["security", "crypto", "cwe-327"],
        },
    ),
    "SVM009": ReportingDescriptor(
        id="SVM009",
        name="CodeInjection",
        short_description="Code Injection vulnerability detected",
        full_description=(
            "User-controlled input is passed to code execution functions like eval(), "
            "allowing arbitrary code execution."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/94.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "injection", "cwe-94"],
        },
    ),
    "SVM010": ReportingDescriptor(
        id="SVM010",
        name="DivisionByZero",
        short_description="Potential division by zero",
        full_description="A division operation may fail due to a zero divisor.",
        help_uri="https://cwe.mitre.org/data/definitions/369.html",
        default_level="warning",
        properties={
            "tags": ["reliability", "cwe-369"],
        },
    ),
    "SVM011": ReportingDescriptor(
        id="SVM011",
        name="AssertionFailure",
        short_description="Assertion may fail",
        full_description="An assertion condition may be false under certain inputs.",
        default_level="warning",
        properties={
            "tags": ["reliability"],
        },
    ),
    "SVM012": ReportingDescriptor(
        id="SVM012",
        name="IndexError",
        short_description="Potential index out of bounds",
        full_description="An array or list access may be out of bounds.",
        help_uri="https://cwe.mitre.org/data/definitions/129.html",
        default_level="warning",
        properties={
            "tags": ["reliability", "cwe-129"],
        },
    ),
    "SVM013": ReportingDescriptor(
        id="SVM013",
        name="UnusedVariable",
        short_description="Unused variable detected",
        full_description="A variable is assigned a value but never used.",
        default_level="note",
        properties={
            "tags": ["maintainability"],
        },
    ),
    "SVM014": ReportingDescriptor(
        id="SVM014",
        name="KeyError",
        short_description="Potential KeyError",
        full_description="A dictionary access may fail due to a missing key.",
        default_level="warning",
        properties={
            "tags": ["reliability"],
        },
    ),
}

__all__ = ["SECURITY_RULES_RELIABILITY"]
