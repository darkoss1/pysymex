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

"""Z3 AST views for constraint independence slicing."""

from __future__ import annotations

import z3

from pysymex._internal.core.solver.independence.protocols import has_to_z3


class IndependenceZ3Ops:
    """Domain owner for Z3 expression coercion and dependency tokens."""

    @staticmethod
    def decl_dependency_token(decl: z3.FuncDeclRef) -> str:
        """Return a stable dependency token for an uninterpreted function declaration."""
        token = getattr(decl, "_symex_dep_token", None)
        if token is None:
            domain = ",".join(str(decl.domain(i)) for i in range(decl.arity()))
            token = f"uf:{decl.name()}({domain})->{decl.range()}"
            try:
                setattr(decl, "_symex_dep_token", token)
            except AttributeError:
                pass
        return token

    @staticmethod
    def as_z3_expr(value: object) -> z3.ExprRef | None:
        """Return a Z3 expression view of ``value``, or ``None`` if unsupported."""
        if isinstance(value, z3.ExprRef):
            return value
        if has_to_z3(value):
            return value.to_z3()
        return None
