"""Type stubs for Python standard library — slim hub with re-exports.

Extraction modules:
  - type_stubs_types: StubType, FunctionStub, ClassStub, ModuleStub
  - type_stubs_core: StubParser, StubRepository, StubBasedTypeResolver, BuiltinStubs
"""

from pysymex.analysis.type_stubs.core import BuiltinStubs as BuiltinStubs
from pysymex.analysis.type_stubs.core import (
    StubBasedTypeResolver as StubBasedTypeResolver,
)
from pysymex.analysis.type_stubs.core import StubParser as StubParser
from pysymex.analysis.type_stubs.core import StubRepository as StubRepository
from pysymex.analysis.type_stubs.types import ClassStub as ClassStub
from pysymex.analysis.type_stubs.types import FunctionStub as FunctionStub
from pysymex.analysis.type_stubs.types import ModuleStub as ModuleStub
from pysymex.analysis.type_stubs.types import StubType as StubType

__all__ = [
    "BuiltinStubs",
    "ClassStub",
    "FunctionStub",
    "ModuleStub",
    "StubBasedTypeResolver",
    "StubParser",
    "StubRepository",
    "StubType",
]
