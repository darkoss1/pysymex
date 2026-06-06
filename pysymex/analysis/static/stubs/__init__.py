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

"""Type stubs for Python standard library — slim hub with re-exports.

Extraction modules:
  - type_stubs_types: StubType, FunctionStub, ClassStub, ModuleStub
  - type_stubs_core: StubParser, StubRepository, StubBasedTypeResolver, BuiltinStubs
"""

from pysymex.analysis.static.stubs.builtins import BuiltinStubs
from pysymex.analysis.static.stubs.parser import StubParser
from pysymex.analysis.static.stubs.repository import StubRepository
from pysymex.analysis.static.stubs.resolver import StubBasedTypeResolver
from pysymex.analysis.static.stubs.types import ClassStub
from pysymex.analysis.static.stubs.types import FunctionStub
from pysymex.analysis.static.stubs.types import ModuleStub
from pysymex.analysis.static.stubs.types import StubType

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
