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

"""Semantic Z3 declaration name registry."""

from __future__ import annotations

try:
    import z3
except ImportError:
    z3 = None


from threading import Lock

from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)


class Z3SemanticRegistry:
    """Thread-safe registry mapping opaque Z3 declaration names to semantic ones."""

    def __init__(self) -> None:
        """Initialize a thread-safe name registry for Z3 declaration mappings."""
        self.lock = Lock()

        self._auto: dict[str, str] = {}
        self._overrides: dict[str, str] = {}

    def register(self, z3_var: object, semantic_name: str) -> None:
        """Register a Z3 expression's declaration name to a semantic name."""
        if z3 is None:
            return
        try:
            if isinstance(z3_var, z3.ExprRef):
                decl_name: str = z3_var.decl().name()
                with self.lock:
                    self._auto[decl_name] = semantic_name
        except Exception:
            logger.debug("Failed to register semantic Z3 declaration name", exc_info=True)

    def update(self, overrides: dict[str, str]) -> None:
        """Apply manual name-override mappings."""
        with self.lock:
            self._overrides.update(overrides)

    def lookup(self, z3_decl_name: str) -> str:
        """Return the semantic name for a Z3 declaration name, or the original."""
        with self.lock:
            return self._overrides.get(z3_decl_name) or self._auto.get(z3_decl_name) or z3_decl_name

    def snapshot(self) -> dict[str, str]:
        """Return a read-only copy of the combined name mapping."""
        with self.lock:
            merged = dict(self._auto)
            merged.update(self._overrides)
            return merged
