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

"""Trace analyzer filter criteria contract."""

from __future__ import annotations

from typing import Protocol


class TraceFilterCriteria(Protocol):
    """Structural filter criteria consumed by trace analyzer filter builders."""

    event_type: list[str] | None
    seq: int | None
    seq_range: tuple[int, int] | None
    path_id: int | None
    path_id_list: list[int] | None
    pc: int | None
    pc_range: tuple[int, int] | None
    opcode: str | None
    source_line: int | None
    step_latency_min: float | None
    step_latency_max: float | None
    has_stack_push: bool
    has_stack_pop: bool
    has_var_modified: bool
    var_modified_name: str | None
    has_var_added: bool
    var_added_name: str | None
    has_var_removed: bool
    var_removed_name: str | None
    has_mem_write: bool
    has_constraint_added: bool
    constraint_causality_contains: str | None
    trigger: str | None
    depth: int | None
    depth_min: int | None
    depth_max: int | None
    parent_path_id: int | None
    has_child_fork: bool
    prune_reason: str | None
    stack_contains: str | None
    local_var_name: str | None
    global_var_name: str | None
    constraint_smtlib_contains: str | None
    num_path_constraints_min: int | None
    num_path_constraints_max: int | None
    solve_result: str | None
    cache_hit: bool
    cache_miss: bool
    solver_latency_min: float | None
    solver_latency_max: float | None
    num_constraints_min: int | None
    num_constraints_max: int | None
    has_model_excerpt: bool
    model_var_name: str | None
    severity: list[str] | None
    detector: str | None
    issue_kind: str | None
    message_contains: str | None
    has_z3_model: bool
    z3_model_var: str | None
    issue_source_line: int | None
    confidence: tuple[float, float] | None
    constraint_at_issue_contains: str | None
    function_name: str | None
    source_file: str | None
    pysymex_version: str | None
    z3_version: str | None
    touches_var: str | None
    constraint_contains: str | None
    any_field_contains: str | None
