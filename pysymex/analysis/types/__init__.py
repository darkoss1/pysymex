# pysymex: Python Symbolic Execution & Formal Verification
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

"""Type-system package for analysis layer.

Canonical blueprint namespace for type inference, environments, constraints,
and type-stub generation.
"""

from __future__ import annotations

from pysymex.analysis.types.constraints import (
    Protocol,
    ProtocolChecker,
    SymbolicType,
    TypeConstraintChecker,
    TypeIssue,
    TypeIssueKind,
    TypeKind,
    Variance,
)
from pysymex.analysis.types.environment import TypeEnvironment
from pysymex.analysis.types.inference import (
    ConfidenceScore,
    TypeAnalyzer,
    TypeInferenceEngine,
    get_type_analyzer,
)
from pysymex.analysis.types.kinds import PyType
from pysymex.analysis.types.patterns import PatternRecognizer, TypeState, TypeStateMachine
from pysymex.analysis.types.stubs import (
    BuiltinStubs,
    ClassStub,
    FunctionStub,
    ModuleStub,
    StubBasedTypeResolver,
    StubParser,
    StubRepository,
    StubType,
)

__all__ = [
    "ConfidenceScore",
    "BuiltinStubs",
    "ClassStub",
    "FunctionStub",
    "ModuleStub",
    "PatternRecognizer",
    "Protocol",
    "ProtocolChecker",
    "PyType",
    "SymbolicType",
    "StubBasedTypeResolver",
    "StubParser",
    "StubRepository",
    "StubType",
    "TypeAnalyzer",
    "TypeConstraintChecker",
    "TypeEnvironment",
    "TypeInferenceEngine",
    "TypeIssue",
    "TypeIssueKind",
    "TypeKind",
    "TypeState",
    "TypeStateMachine",
    "Variance",
    "get_type_analyzer",
]
