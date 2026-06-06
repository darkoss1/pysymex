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

"""Z3 AST helper functions for constraint independence."""

from __future__ import annotations

import z3

from pysymex.core.solver.independence.protocols import has_to_z3
from pysymex.logger import get_logger

logger = get_logger(__name__)


def decl_dependency_token(decl: z3.FuncDeclRef) -> str:
    """Return a stable dependency token for an uninterpreted function declaration."""
    domain = ",".join(str(decl.domain(i)) for i in range(decl.arity()))
    return f"uf:{decl.name()}({domain})->{decl.range()}"


def expr_theory_signature(expr: z3.ExprRef) -> tuple[str, ...]:
    """Return cached-key metadata describing observed AST sorts and kinds.

    Limitations:
        Equal signatures are not proof of semantic equivalence.
    """
    tokens: set[str] = set()
    worklist: list[z3.ExprRef] = [expr]
    seen_ids: set[int] = {expr.get_id()}
    while worklist:
        node = worklist.pop()
        try:
            tokens.add(f"sort:{node.sort()}")
        except z3.Z3Exception:
            if logger.state.debug_enabled:
                logger.debug("Failed to read Z3 sort for theory signature", exc_info=True)
            tokens.add("sort:<unknown>")
        if z3.is_quantifier(node):
            tokens.add("kind:quantifier_forall" if node.is_forall() else "kind:quantifier_exists")
            body = node.body()
            body_id = body.get_id()
            if body_id not in seen_ids:
                seen_ids.add(body_id)
                worklist.append(body)
            continue
        if not z3.is_app(node):
            tokens.add("kind:non_app")
            continue
        decl = node.decl()
        tokens.add(f"kind:{decl.kind()}")
        if decl.kind() == z3.Z3_OP_UNINTERPRETED:
            tokens.add(decl_dependency_token(decl))
        for child in node.children():
            child_id = child.get_id()
            if child_id not in seen_ids:
                seen_ids.add(child_id)
                worklist.append(child)
    return tuple(sorted(tokens))


def as_z3_expr(value: object) -> z3.ExprRef | None:
    """Return a Z3 expression view of ``value``, or ``None`` if unsupported."""
    if isinstance(value, z3.ExprRef):
        return value
    if has_to_z3(value):
        return value.to_z3()
    return None


__all__ = ["as_z3_expr", "decl_dependency_token", "expr_theory_signature"]
