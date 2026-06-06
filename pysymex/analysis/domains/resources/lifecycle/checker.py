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

"""Top-level resource lifecycle checker coordinating file, lock, and policy checks."""

from __future__ import annotations

import z3

from pysymex.analysis.domains.resources.lifecycle.policy import ResourceLifecyclePolicy
from pysymex.analysis.domains.resources.types import (
    ResourceIssue,
    ResourceKind,
    ResourceSafetyProof,
)


class ResourceLifecycleChecker(ResourceLifecyclePolicy):
    """Comprehensive resource lifecycle checker using Z3."""

    def prove_resource_safety(
        self,
        resource_name: str,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool, str | None]:
        proof = self.prove_resource_safety_result(resource_name, path_constraints)
        return proof.as_legacy_tuple()

    def prove_resource_safety_result(
        self,
        resource_name: str,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ResourceSafetyProof:
        """Prove resource cleanup safety without collapsing solver uncertainty."""
        resource = self._resources.get(resource_name)
        if resource is None:
            return ResourceSafetyProof.not_tracked()
        constraints = list(path_constraints or [])
        z3_state = resource.z3_state
        final_states = [
            self._state_consts[state]
            for state in getattr(resource.state_machine, "_final_states", ())
        ]
        safety_property = z3.Or(*[z3_state == final_state for final_state in final_states])
        result = self.solver.check_sat_result([*constraints, z3.Not(safety_property)])
        if result.is_unsat:
            return ResourceSafetyProof.proven_safe()
        if result.is_unknown:
            return ResourceSafetyProof.inconclusive()
        return ResourceSafetyProof.unsafe()

    def get_all_issues(self) -> list[ResourceIssue]:
        all_issues = list(self.issues)
        all_issues.extend(self.check_leaks())
        for name, resource in self._resources.items():
            if resource.kind == ResourceKind.DATABASE_TRANSACTION:
                issue = self.check_transaction_state(name)
                if issue:
                    all_issues.append(issue)
        return all_issues

    def get_resource_summary(self) -> dict[str, object]:
        return {
            name: {
                "kind": resource.kind.name,
                "state": resource.state.name,
                "created_at": resource.created_at,
                "is_final": resource.state_machine.is_final_state(resource.state),
                "history_length": len(resource.history),
            }
            for name, resource in self._resources.items()
        }
