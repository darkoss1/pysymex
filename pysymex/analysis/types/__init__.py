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
