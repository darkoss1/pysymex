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

"""Core type inference engine: bytecode-driven type propagation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.analysis.static.types.engine.annotations import TypeAnnotationInferenceMixin
from pysymex.analysis.static.types.engine.attributes import TypeAttributeInferenceMixin
from pysymex.analysis.static.types.engine.operations import TypeOperationInferenceMixin
from pysymex.analysis.static.types.engine.values import TypeValueInferenceMixin
from pysymex.analysis.static.types.kinds import PyType

if TYPE_CHECKING:
    from pysymex.analysis.static.stubs.resolver import StubBasedTypeResolver


class _UnavailableStubResolver:
    pass


_STUB_RESOLVER_UNAVAILABLE = _UnavailableStubResolver()


class TypeInferenceEngine(
    TypeAttributeInferenceMixin,
    TypeAnnotationInferenceMixin,
    TypeValueInferenceMixin,
    TypeOperationInferenceMixin,
):
    """
    Main type inference engine.
    Performs:
    - Forward type propagation
    - Flow-sensitive type narrowing
    - Pattern-based inference
    - Type annotation integration
    """

    def __init__(self) -> None:
        self.function_signatures: dict[str, tuple[list[PyType], PyType]] = {}
        self._stub_resolver: StubBasedTypeResolver | _UnavailableStubResolver | None = None

    @property
    def stub_resolver(self) -> StubBasedTypeResolver | None:
        """Lazy-load stub resolver to avoid circular imports."""
        if self._stub_resolver is None:
            try:
                from pysymex.analysis.static.stubs.resolver import StubBasedTypeResolver

                self._stub_resolver = StubBasedTypeResolver()
            except ImportError:
                self._stub_resolver = _STUB_RESOLVER_UNAVAILABLE
        if isinstance(self._stub_resolver, _UnavailableStubResolver):
            return None
        return self._stub_resolver
