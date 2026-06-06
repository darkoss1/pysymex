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

"""Warning types shared across string analysis sub-modules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class StringWarningKind(Enum):
    """Types of string-related warnings."""

    FORMAT_STRING_MISMATCH = auto()
    MISSING_FORMAT_ARG = auto()
    EXTRA_FORMAT_ARG = auto()
    INVALID_FORMAT_SPEC = auto()
    INVALID_REGEX = auto()
    REGEX_PERFORMANCE = auto()
    ENCODING_ERROR = auto()
    STRING_MULTIPLICATION = auto()
    SQL_INJECTION = auto()
    PATH_TRAVERSAL = auto()


@dataclass
class StringWarning:
    """Warning about string operations."""

    kind: StringWarningKind
    file: str
    line: int
    message: str
    code_snippet: str = ""
    severity: str = "warning"
