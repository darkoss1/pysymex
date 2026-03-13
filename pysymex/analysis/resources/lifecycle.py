"""Advanced Resource Lifecycle Analysis with Z3.

This module provides comprehensive resource lifecycle checking using Z3 SMT solver.

Implementation split for maintainability:
- lifecycle_types: Enums (ResourceKind, ResourceState, ResourceIssueKind), dataclasses
- lifecycle_state_machines: ResourceStateMachine, TrackedResource
- This file (hub): ResourceLifecycleChecker, FileResourceChecker, LockResourceChecker
"""

from __future__ import annotations

import z3

from pysymex.analysis.resources.lifecycle_state_machines import (
    ResourceStateMachine,
    TrackedResource,
)
from pysymex.analysis.resources.lifecycle_types import (
    ResourceIssue,
    ResourceIssueKind,
    ResourceKind,
    ResourceState,
    StateTransition,
)


class ResourceLifecycleChecker:
    """
    Comprehensive resource lifecycle checker using Z3.

    Tracks resources through state machines and proves
    safety properties via SMT solving.
    """

    def __init__(self, timeout_ms: int = 5000):
        """Init."""
        """Initialize the class instance."""
        self.timeout_ms = timeout_ms
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)
        self._resources: dict[str, TrackedResource] = {}
        self._issues: list[ResourceIssue] = []
        self.StateSort = z3.DeclareSort("ResourceState")
        self._state_consts: dict[ResourceState, z3.ExprRef] = {}
        self._setup_state_encoding()

    def _setup_state_encoding(self) -> None:
        """Set up Z3 encoding for states."""
        for state in ResourceState:
            self._state_consts[state] = z3.Const(f"state_{state .name }", self.StateSort)

    def reset(self) -> None:
        """Reset checker state."""
        self._solver.reset()
        self._resources.clear()
        self._issues.clear()

    def _path_is_feasible(self, path_constraints: list[z3.BoolRef] | None) -> bool:
        """Return whether the current path constraints are satisfiable."""
        if not path_constraints:
            return True
        self._solver.push()
        try:
            self._solver.add(*path_constraints)
            return self._solver.check() == z3.sat
        finally:
            self._solver.pop()

    def create_resource(
        self,
        name: str,
        kind: ResourceKind,
        line_number: int | None = None,
    ) -> TrackedResource:
        """Create and start tracking a new resource."""
        state_machine = ResourceStateMachine(kind)
        resource = TrackedResource(
            name=name,
            kind=kind,
            state=state_machine.initial_state,
            state_machine=state_machine,
            created_at=line_number,
            z3_state=z3.Const(f"{name }_state", self.StateSort),
        )
        self._resources[name] = resource
        return resource

    def get_resource(self, name: str) -> TrackedResource | None:
        """Get a tracked resource by name."""
        return self._resources.get(name)

    def check_action(
        self,
        resource_name: str,
        action: str,
        line_number: int | None = None,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ResourceIssue | None:
        """
        Check if an action is valid for a resource.

        Args:
            resource_name: Name of the resource
            action: Action being performed
            line_number: Current line number
            path_constraints: Current path constraints

        Returns:
            Issue if action is invalid, None otherwise
        """
        if not self._path_is_feasible(path_constraints):
            return None

        resource = self._resources.get(resource_name)
        if resource is None:
            return ResourceIssue(
                kind=ResourceIssueKind.MISSING_INITIALIZATION,
                message=f"Resource '{resource_name }' not initialized",
                resource_name=resource_name,
                line_number=line_number,
            )
        transition = resource.state_machine.get_transition(resource.state, action)
        if transition is None:
            return ResourceIssue(
                kind=ResourceIssueKind.INVALID_STATE_TRANSITION,
                message=f"Cannot perform '{action }' on resource in state {resource .state .name }",
                resource_kind=resource.kind,
                resource_name=resource_name,
                current_state=resource.state,
                line_number=line_number,
            )
        resource.record_action(action, transition.to_state, line_number)
        return None

    def perform_action(
        self,
        resource_name: str,
        action: str,
        line_number: int | None = None,
    ) -> tuple[ResourceState | None, ResourceIssue | None]:
        """
        Perform action and return (new_state, issue).
        """
        issue = self.check_action(resource_name, action, line_number)
        if issue:
            return (None, issue)
        resource = self._resources[resource_name]
        return (resource.state, None)

    def check_leaks(
        self,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[ResourceIssue]:
        """
        Check all tracked resources for potential leaks.

        A leak occurs when a resource reaches the end of scope
        without being in a final state.
        """
        issues: list[ResourceIssue] = []
        active_constraints = list(path_constraints or [])
        if not self._path_is_feasible(active_constraints):
            return issues
        for name, resource in self._resources.items():
            if not resource.state_machine.is_final_state(resource.state):
                issues.append(
                    ResourceIssue(
                        kind=ResourceIssueKind.RESOURCE_LEAK,
                        message=f"Resource '{name }' not properly closed/released",
                        resource_kind=resource.kind,
                        resource_name=name,
                        current_state=resource.state,
                        expected_states=list(resource.state_machine._final_states),
                        constraints=list(active_constraints),
                    )
                )
        return issues

    def check_potential_leak(
        self,
        resource_name: str,
        exception_possible: bool = True,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ResourceIssue | None:
        """
        Check if resource could leak due to exceptions.

        If an exception can occur between open and close,
        the resource may leak.
        """
        if not self._path_is_feasible(path_constraints):
            return None

        resource = self._resources.get(resource_name)
        if resource is None:
            return None
        if not resource.state_machine.is_final_state(resource.state) and exception_possible:
            return ResourceIssue(
                kind=ResourceIssueKind.POTENTIAL_LEAK,
                message=f"Resource '{resource_name }' may leak if exception occurs",
                resource_kind=resource.kind,
                resource_name=resource_name,
                current_state=resource.state,
                constraints=list(path_constraints or []),
                severity="warning",
            )
        return None

    def check_use_after(
        self,
        resource_name: str,
        action: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """
        Check for use-after-close/free/release.
        """
        resource = self._resources.get(resource_name)
        if resource is None:
            return None
        dead_states = {
            ResourceState.CLOSED,
            ResourceState.FILE_CLOSED,
            ResourceState.FREED,
            ResourceState.RELEASED,
            ResourceState.DISCONNECTED,
        }
        if resource.state in dead_states:
            if resource.state in {ResourceState.CLOSED, ResourceState.FILE_CLOSED}:
                kind = ResourceIssueKind.USE_AFTER_CLOSE
            elif resource.state == ResourceState.FREED:
                kind = ResourceIssueKind.USE_AFTER_FREE
            else:
                kind = ResourceIssueKind.USE_AFTER_RELEASE
            return ResourceIssue(
                kind=kind,
                message=f"Using '{resource_name }' after {resource .state .name }",
                resource_kind=resource.kind,
                resource_name=resource_name,
                current_state=resource.state,
                line_number=line_number,
            )
        return None

    def check_double_operation(
        self,
        resource_name: str,
        action: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """
        Check for double close/free/release.
        """
        resource = self._resources.get(resource_name)
        if resource is None:
            return None
        if action in {"close", "free", "release", "disconnect"}:
            dead_states = {
                ResourceState.CLOSED,
                ResourceState.FILE_CLOSED,
                ResourceState.FREED,
                ResourceState.RELEASED,
                ResourceState.LOCK_UNLOCKED,
                ResourceState.DISCONNECTED,
            }
            if resource.state in dead_states:
                if action == "close":
                    kind = ResourceIssueKind.DOUBLE_CLOSE
                elif action == "free":
                    kind = ResourceIssueKind.DOUBLE_FREE
                elif action == "release":
                    kind = ResourceIssueKind.DOUBLE_RELEASE
                else:
                    kind = ResourceIssueKind.DOUBLE_CLOSE
                return ResourceIssue(
                    kind=kind,
                    message=f"Double {action } on '{resource_name }'",
                    resource_kind=resource.kind,
                    resource_name=resource_name,
                    current_state=resource.state,
                    line_number=line_number,
                )
        if action in {"acquire", "lock"}:
            if resource.state == ResourceState.LOCK_LOCKED:
                return ResourceIssue(
                    kind=ResourceIssueKind.DOUBLE_ACQUIRE,
                    message=f"Acquiring already held lock '{resource_name }'",
                    resource_kind=resource.kind,
                    resource_name=resource_name,
                    current_state=resource.state,
                    line_number=line_number,
                )
        return None

    def check_lock_ordering(
        self,
        locks: list[str],
        expected_order: list[str],
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """
        Check if locks are acquired in the expected order.

        Lock ordering is important for deadlock prevention.
        """
        actual_order: list[str] = []
        for lock_name in locks:
            resource = self._resources.get(lock_name)
            if resource is None:
                continue
            for action, _state, _ in resource.history:
                if action == "acquire" and lock_name not in actual_order:
                    actual_order.append(lock_name)
        for i, lock in enumerate(actual_order):
            if lock not in expected_order:
                continue
            expected_idx = expected_order.index(lock)
            for prev_lock in actual_order[:i]:
                if prev_lock in expected_order:
                    prev_expected_idx = expected_order.index(prev_lock)
                    if prev_expected_idx > expected_idx:
                        return ResourceIssue(
                            kind=ResourceIssueKind.LOCK_ORDER_VIOLATION,
                            message=f"Lock order violation: {prev_lock } acquired before {lock }",
                            resource_name=lock,
                            line_number=line_number,
                        )
        return None

    def check_potential_deadlock(
        self,
        lock_dependencies: dict[str, set[str]],
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ResourceIssue | None:
        """
        Check for potential deadlock using cycle detection.

        Args:
            lock_dependencies: Map of lock -> locks it waits for while held
        """
        if not self._path_is_feasible(path_constraints):
            return None

        visited: set[str] = set()
        rec_stack: set[str] = set()

        def has_cycle(lock: str) -> bool:
            """Has cycle."""
            visited.add(lock)
            rec_stack.add(lock)
            for dep in lock_dependencies.get(lock, set()):
                if dep not in visited:
                    if has_cycle(dep):
                        return True
                elif dep in rec_stack:
                    return True
            rec_stack.remove(lock)
            return False

        for lock in lock_dependencies:
            if lock not in visited:
                if has_cycle(lock):
                    return ResourceIssue(
                        kind=ResourceIssueKind.DEADLOCK_POTENTIAL,
                        message=f"Potential deadlock detected involving lock '{lock }'",
                        resource_name=lock,
                        constraints=list(path_constraints or []),
                    )
        return None

    def check_transaction_state(
        self,
        resource_name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """
        Check if transaction is in a valid state.

        Uncommitted transactions should not exist at function exit.
        """
        resource = self._resources.get(resource_name)
        if resource is None or resource.kind != ResourceKind.DATABASE_TRANSACTION:
            return None
        if resource.state == ResourceState.TRANSACTION_ACTIVE:
            return ResourceIssue(
                kind=ResourceIssueKind.UNCOMMITTED_TRANSACTION,
                message=f"Transaction '{resource_name }' not committed or rolled back",
                resource_kind=resource.kind,
                resource_name=resource_name,
                current_state=resource.state,
                line_number=line_number,
            )
        return None

    def suggest_context_manager(
        self,
        resource_name: str,
    ) -> ResourceIssue | None:
        """
        Suggest using a context manager for safer resource handling.
        """
        resource = self._resources.get(resource_name)
        if resource is None:
            return None
        cm_kinds = {
            ResourceKind.FILE,
            ResourceKind.LOCK,
            ResourceKind.MUTEX,
            ResourceKind.DATABASE_CONNECTION,
            ResourceKind.SOCKET,
        }
        if resource.kind in cm_kinds:
            has_other_operations = len(resource.history) > 2
            if has_other_operations:
                return ResourceIssue(
                    kind=ResourceIssueKind.MISSING_CONTEXT_MANAGER,
                    message=f"Consider using 'with' statement for '{resource_name }'",
                    resource_kind=resource.kind,
                    resource_name=resource_name,
                    severity="info",
                )
        return None

    def prove_resource_safety(
        self,
        resource_name: str,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool, str | None]:
        """
        Prove that a resource is always properly managed.

        Returns (is_safe, counterexample_if_not).
        """
        resource = self._resources.get(resource_name)
        if resource is None:
            return (False, "Resource not tracked")
        constraints = list(path_constraints or [])
        z3_state = resource.z3_state
        final_states = [self._state_consts[s] for s in resource.state_machine._final_states]
        safety_property = z3.Or(*[z3_state == fs for fs in final_states])
        self._solver.push()
        for c in constraints:
            self._solver.add(c)
        self._solver.add(z3.Not(safety_property))
        result = self._solver.check()
        self._solver.pop()
        if result == z3.unsat:
            return (True, None)
        else:
            return (False, "Resource may not be properly closed/released")

    def get_all_issues(self) -> list[ResourceIssue]:
        """Get all detected issues including leak checks."""
        all_issues = list(self._issues)
        all_issues.extend(self.check_leaks())
        for name, resource in self._resources.items():
            if resource.kind == ResourceKind.DATABASE_TRANSACTION:
                issue = self.check_transaction_state(name)
                if issue:
                    all_issues.append(issue)
        return all_issues

    def get_resource_summary(self) -> dict[str, object]:
        """Get summary of all tracked resources."""
        return {
            name: {
                "kind": res.kind.name,
                "state": res.state.name,
                "created_at": res.created_at,
                "is_final": res.state_machine.is_final_state(res.state),
                "history_length": len(res.history),
            }
            for name, res in self._resources.items()
        }


class FileResourceChecker(ResourceLifecycleChecker):
    """Specialized checker for file resources."""

    def open_file(
        self,
        name: str,
        mode: str = "r",
        line_number: int | None = None,
    ) -> tuple[TrackedResource, ResourceIssue | None]:
        """Track opening a file."""
        resource = self.create_resource(name, ResourceKind.FILE, line_number)
        if "w" in mode:
            action = "open_write"
        elif "a" in mode:
            action = "open_append"
        elif "+" in mode:
            action = "open_readwrite"
        else:
            action = "open_read"
        issue = self.check_action(name, action, line_number)
        return (resource, issue)

    def read_file(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """Track reading from a file."""
        issue = self.check_use_after(name, "read", line_number)
        if issue:
            return issue
        return self.check_action(name, "read", line_number)

    def write_file(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """Track writing to a file."""
        issue = self.check_use_after(name, "write", line_number)
        if issue:
            return issue
        return self.check_action(name, "write", line_number)

    def close_file(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """Track closing a file."""
        issue = self.check_double_operation(name, "close", line_number)
        if issue:
            return issue
        return self.check_action(name, "close", line_number)


class LockResourceChecker(ResourceLifecycleChecker):
    """Specialized checker for lock resources."""

    def __init__(self, timeout_ms: int = 5000):
        """Init."""
        """Initialize the class instance."""
        super().__init__(timeout_ms)
        self._lock_order: list[str] = []
        self._held_locks: set[str] = set()

    def create_lock(
        self,
        name: str,
        line_number: int | None = None,
    ) -> TrackedResource:
        """Create a new lock."""
        return self.create_resource(name, ResourceKind.LOCK, line_number)

    def acquire_lock(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """Track acquiring a lock."""
        if name in self._held_locks:
            return ResourceIssue(
                kind=ResourceIssueKind.DOUBLE_ACQUIRE,
                message=f"Lock '{name }' already held by this thread",
                resource_name=name,
                line_number=line_number,
            )
        issue = self.check_action(name, "acquire", line_number)
        if issue is None:
            self._held_locks.add(name)
        return issue

    def release_lock(
        self,
        name: str,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """Track releasing a lock."""
        if name not in self._held_locks:
            return ResourceIssue(
                kind=ResourceIssueKind.DOUBLE_RELEASE,
                message=f"Lock '{name }' not held",
                resource_name=name,
                line_number=line_number,
            )
        issue = self.check_action(name, "release", line_number)
        if issue is None:
            self._held_locks.discard(name)
        return issue

    def set_lock_order(self, order: list[str]) -> None:
        """Set expected lock acquisition order."""
        self._lock_order = order

    def check_current_lock_order(
        self,
        line_number: int | None = None,
    ) -> ResourceIssue | None:
        """Check if current lock holdings follow expected order."""
        if not self._lock_order:
            return None
        return self.check_lock_ordering(
            list(self._held_locks),
            self._lock_order,
            line_number,
        )


__all__ = [
    "FileResourceChecker",
    "LockResourceChecker",
    "ResourceIssue",
    "ResourceIssueKind",
    "ResourceKind",
    "ResourceLifecycleChecker",
    "ResourceState",
    "ResourceStateMachine",
    "StateTransition",
    "TrackedResource",
]
