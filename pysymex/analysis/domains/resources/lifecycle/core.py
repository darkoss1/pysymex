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

"""Core resource lifecycle tracking and transition checks."""

from __future__ import annotations

import z3

from pysymex.analysis.domains.resources.lifecycle.state_machine import ResourceStateMachine
from pysymex.analysis.domains.resources.lifecycle.tracked import TrackedResource
from pysymex.analysis.domains.resources.types import (
    ResourceIssue,
    ResourceIssueKind,
    ResourceKind,
    ResourceState,
)
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult


class ResourceLifecycleCore:
    """Core resource lifecycle checker using Z3-backed path feasibility."""

    def __init__(self, timeout_ms: int = 5000) -> None:
        self.timeout_ms = timeout_ms
        self.solver = IncrementalSolver(timeout_ms=timeout_ms)
        self._resources: dict[str, TrackedResource] = {}
        self.issues: list[ResourceIssue] = []
        self.StateSort = z3.DeclareSort("ResourceState")
        self._state_consts: dict[ResourceState, z3.ExprRef] = {}
        self._setup_state_encoding()

    def _setup_state_encoding(self) -> None:
        for state in ResourceState:
            self._state_consts[state] = z3.Const(f"state_{state.name}", self.StateSort)

    def _path_feasibility_result(self, path_constraints: list[z3.BoolRef] | None) -> SolverResult:
        if not path_constraints:
            return SolverResult.sat(None)
        return self.solver.check_sat_result(path_constraints)

    def _path_is_feasible(self, path_constraints: list[z3.BoolRef] | None) -> bool:
        return not self._path_feasibility_result(path_constraints).is_unsat

    @staticmethod
    def _issue_severity_for_feasibility(path_result: SolverResult) -> str:
        if path_result.is_unknown:
            return "warning"
        return "error"

    def create_resource(
        self,
        name: str,
        kind: ResourceKind,
        line_number: int | None = None,
    ) -> TrackedResource:
        state_machine = ResourceStateMachine(kind)
        resource = TrackedResource(
            name=name,
            kind=kind,
            state=state_machine.initial_state,
            state_machine=state_machine,
            created_at=line_number,
            z3_state=z3.Const(f"{name}_state", self.StateSort),
        )
        self._resources[name] = resource
        return resource

    def check_action(
        self,
        resource_name: str,
        action: str,
        line_number: int | None = None,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ResourceIssue | None:
        path_result = self._path_feasibility_result(path_constraints)
        if path_result.is_unsat:
            return None
        severity = self._issue_severity_for_feasibility(path_result)

        resource = self._resources.get(resource_name)
        if resource is None:
            return ResourceIssue(
                kind=ResourceIssueKind.MISSING_INITIALIZATION,
                message=f"Resource '{resource_name}' not initialized",
                resource_name=resource_name,
                line_number=line_number,
                severity=severity,
            )
        transition = resource.state_machine.get_transition(resource.state, action)
        if transition is None:
            return ResourceIssue(
                kind=ResourceIssueKind.INVALID_STATE_TRANSITION,
                message=f"Cannot perform '{action}' on resource in state {resource.state.name}",
                resource_kind=resource.kind,
                resource_name=resource_name,
                current_state=resource.state,
                line_number=line_number,
                severity=severity,
            )
        resource.record_action(action, transition.to_state, line_number)
        return None

    def check_leaks(
        self,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[ResourceIssue]:
        issues: list[ResourceIssue] = []
        active_constraints = list(path_constraints or [])
        path_result = self._path_feasibility_result(active_constraints)
        if path_result.is_unsat:
            return issues
        severity = self._issue_severity_for_feasibility(path_result)
        for name, resource in self._resources.items():
            if not resource.state_machine.is_final_state(resource.state):
                issues.append(
                    ResourceIssue(
                        kind=ResourceIssueKind.RESOURCE_LEAK,
                        message=f"Resource '{name}' not properly closed/released",
                        resource_kind=resource.kind,
                        resource_name=name,
                        current_state=resource.state,
                        expected_states=list(getattr(resource.state_machine, "_final_states", ())),
                        constraints=list(active_constraints),
                        severity=severity,
                    )
                )
        return issues
