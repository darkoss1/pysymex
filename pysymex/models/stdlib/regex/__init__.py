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

"""Symbolic Models for Python's re module."""

from __future__ import annotations

from pysymex.models.stdlib.regex.compiler import (
    PatternCompiler,
    compile_pattern,
)
from pysymex.models.stdlib.regex.matching import (
    ReFullmatchModel,
    ReMatchModel,
    ReSearchModel,
)
from pysymex.models.stdlib.regex.registry import (
    REGEX_MODELS,
    ReCompileModel,
    ReEscapeModel,
)
from pysymex.models.stdlib.regex.sequences import (
    ReFindallModel,
    ReSplitModel,
    ReSubModel,
)

__all__ = [
    "PatternCompiler",
    "REGEX_MODELS",
    "ReCompileModel",
    "ReEscapeModel",
    "ReFindallModel",
    "ReFullmatchModel",
    "ReMatchModel",
    "ReSearchModel",
    "ReSplitModel",
    "ReSubModel",
    "compile_pattern",
]
