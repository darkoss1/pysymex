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

"""Type inference: propagate types through bytecode for downstream analyses."""

from __future__ import annotations

from pysymex.analysis.static.types.analyzer import (
    ConfidenceScore,
    TypeAnalyzer,
    get_type_analyzer,
)
from pysymex.analysis.static.types.engine.core import TypeInferenceEngine
from pysymex.analysis.static.types.env import TypeEnvironment
from pysymex.analysis.static.types.kinds import PyType, TypeKind
from pysymex.analysis.static.types.patterns import (
    PatternRecognizer,
    TypeState,
    TypeStateMachine,
)

__all__ = [
    "ConfidenceScore",
    "PatternRecognizer",
    "PyType",
    "TypeAnalyzer",
    "TypeEnvironment",
    "TypeInferenceEngine",
    "TypeKind",
    "TypeState",
    "TypeStateMachine",
    "get_type_analyzer",
]
