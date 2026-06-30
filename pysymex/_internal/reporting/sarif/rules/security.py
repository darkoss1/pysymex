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

"""Declare SARIF rule descriptors for security vulnerabilities.

Provides rule definitions including severity scores and CWE mappings for injection
vulnerabilities, hardcoded secrets, and cryptographic defects.
"""

from __future__ import annotations

from pysymex._internal.reporting.sarif.types.results import ReportingDescriptor

SECURITY_RULES_SECURITY: dict[str, ReportingDescriptor] = {
    "SVM001": ReportingDescriptor(
        id="SVM001",
        name="CommandInjection",
        short_description="Command Injection vulnerability detected",
        full_description=(
            "User-controlled input is passed to a command execution function "
            "without proper sanitization, allowing attackers to execute arbitrary commands."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/78.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "injection", "cwe-78"],
        },
    ),
    "SVM002": ReportingDescriptor(
        id="SVM002",
        name="SQLInjection",
        short_description="SQL Injection vulnerability detected",
        full_description=(
            "User-controlled input is concatenated into SQL queries "
            "without proper parameterization, allowing SQL injection attacks."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/89.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "injection", "cwe-89"],
        },
    ),
    "SVM003": ReportingDescriptor(
        id="SVM003",
        name="PathTraversal",
        short_description="Path Traversal vulnerability detected",
        full_description=(
            "User-controlled input is used in file path operations "
            "without proper validation, allowing access to arbitrary files."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/22.html",
        default_level="error",
        properties={
            "security-severity": "7.5",
            "tags": ["security", "path-traversal", "cwe-22"],
        },
    ),
    "SVM004": ReportingDescriptor(
        id="SVM004",
        name="SSRF",
        short_description="Server-Side Request Forgery detected",
        full_description=(
            "User-controlled input is used to construct URLs for server-side requests, "
            "potentially allowing access to internal resources."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/918.html",
        default_level="error",
        properties={
            "security-severity": "9.0",
            "tags": ["security", "ssrf", "cwe-918"],
        },
    ),
    "SVM005": ReportingDescriptor(
        id="SVM005",
        name="InsecureDeserialization",
        short_description="Insecure Deserialization detected",
        full_description=(
            "Untrusted data is deserialized using unsafe methods, "
            "potentially allowing remote code execution."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/502.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "deserialization", "cwe-502"],
        },
    ),
    "SVM006": ReportingDescriptor(
        id="SVM006",
        name="TemplateInjection",
        short_description="Server-Side Template Injection detected",
        full_description=(
            "User-controlled input is passed to a template engine, "
            "potentially allowing code execution."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/97.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "injection", "cwe-97"],
        },
    ),
    "SVM007": ReportingDescriptor(
        id="SVM007",
        name="HardcodedSecret",
        short_description="Hardcoded secret detected",
        full_description=(
            "A secret or credential appears to be hardcoded in the source code, "
            "which could lead to unauthorized access if the code is exposed."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/798.html",
        default_level="warning",
        properties={
            "security-severity": "7.5",
            "tags": ["security", "secrets", "cwe-798"],
        },
    ),
}
