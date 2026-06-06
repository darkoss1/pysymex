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

"""Graph state helpers for realtime scans."""

from __future__ import annotations

from pathlib import Path

from pysymex.reporting.realtime.state import RealtimeEdge, RealtimeNode, global_state


def select_scan_files(path: Path, recursive: bool) -> tuple[list[Path], Path]:
    """Resolve scan files and the root directory for graph display."""
    if path.is_file():
        return [path], path.parent
    pattern = "**/*.py" if recursive else "*.py"
    return sorted(path.glob(pattern)), path


def initialize_graph(files: list[Path], root_dir: Path) -> set[str]:
    """Initialize graph nodes/edges for all target files."""
    with global_state.lock:
        global_state.active_file = None
        global_state.issues_list = []
        global_state.visited_functions = []
        global_state.stats.update(
            {
                "paths": 0,
                "total_issues": 0,
                "scan_errors": 0,
                "degraded_scans": 0,
                "pc": 0,
                "opname": "IDLE",
                "files": 0,
                "active_func": "<module>",
            }
        )
        nodes: list[RealtimeNode] = [
            {
                "id": str(root_dir.resolve()),
                "label": root_dir.name,
                "type": "dir",
                "status": "pending",
            }
        ]
        edges: list[RealtimeEdge] = []
        dir_set = {str(root_dir.resolve())}
        for file_path in files:
            parts = file_path.resolve().relative_to(root_dir.resolve()).parts
            current_path = root_dir.resolve()
            for i, part in enumerate(parts):
                parent_path = str(current_path)
                current_path = current_path / part
                curr_str = str(current_path)
                if curr_str not in dir_set:
                    dir_set.add(curr_str)
                    is_file = i == len(parts) - 1
                    nodes.append(
                        {
                            "id": curr_str,
                            "label": part,
                            "type": "file" if is_file else "dir",
                            "status": "pending",
                        }
                    )
                    edges.append({"source": parent_path, "target": curr_str})
        global_state.replace_graph(nodes, edges)
        global_state.touch_stats()
        return dir_set


def mark_file_active(file_path: Path, root_dir: Path, dir_set: set[str]) -> str:
    """Mark a file and its parents as active in the live graph."""
    path_str = str(file_path.resolve())
    with global_state.lock:
        global_state.active_file = file_path
        global_state.set_node_status(path_str, "active")
        parent = file_path.resolve().parent
        while str(parent) in dir_set:
            global_state.set_node_status(str(parent), "active")
            if parent == root_dir.resolve():
                break
            parent = parent.parent
        global_state.touch_stats()
    return path_str


def mark_file_done(
    file_path: Path,
    root_dir: Path,
    dir_set: set[str],
    issue_count: int,
    has_error: bool = False,
    is_degraded: bool = False,
) -> None:
    """Mark a completed file and restore parent directory status."""
    path_str = str(file_path.resolve())
    with global_state.lock:
        global_state.stats["files"] += 1
        global_state.stats["total_issues"] += issue_count
        if has_error:
            global_state.stats["scan_errors"] += 1
            status = "done_error"
        elif is_degraded:
            global_state.stats["degraded_scans"] += 1
            status = "done_degraded"
        else:
            status = "done_issues" if issue_count > 0 else "done_clean"
        global_state.set_node_status(path_str, status)
        parent = file_path.resolve().parent
        while str(parent) in dir_set:
            global_state.set_node_status(str(parent), "pending")
            if parent == root_dir.resolve():
                break
            parent = parent.parent
        global_state.touch_stats()


__all__ = ["initialize_graph", "mark_file_active", "mark_file_done", "select_scan_files"]
