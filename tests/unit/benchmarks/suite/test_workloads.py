# pysymex: Python Symbolic Execution & Formal Verification
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

from __future__ import annotations

from pysymex.benchmarks.suite.workload.registry import create_builtin_benchmarks
from pysymex.benchmarks.suite.types import BenchmarkCategory, BenchmarkMode


def test_create_builtin_benchmarks_is_valid() -> None:
    suite = create_builtin_benchmarks()
    assert len(suite.benchmarks) > 0
    assert any(b.name == "arith_solver" for b in suite.benchmarks)
    assert any(b.name == "cli_scan" for b in suite.benchmarks)
    assert any(b.name == "scanner_scan" for b in suite.benchmarks)
    assert any(b.name == "path_cap" for b in suite.benchmarks)
    assert any(b.name == "string_models" for b in suite.benchmarks)
    assert any(b.name == "formatters" for b in suite.benchmarks)
    assert any(b.name == "detector_scan" for b in suite.benchmarks)
    assert any(b.name == "except_cache" for b in suite.benchmarks)
    assert any(b.name == "line_cache" for b in suite.benchmarks)
    assert any(b.name == "literal_cache" for b in suite.benchmarks)
    assert any(b.name == "sat_cache" for b in suite.benchmarks)
    assert any(b.name == "unsat_cache" for b in suite.benchmarks)
    assert any(b.name == "shadow_admit" for b in suite.benchmarks)
    assert any(b.name == "runtime_admit" for b in suite.benchmarks)
    assert any(b.name == "compact_admit" for b in suite.benchmarks)
    assert any(b.name == "preview_exec" for b in suite.benchmarks)
    assert any(b.name == "preview_unsat" for b in suite.benchmarks)
    assert any(b.name == "cegis_exact" for b in suite.benchmarks)
    assert any(b.name == "cegis_dedupe" for b in suite.benchmarks)
    assert any(b.name == "cegis_core" for b in suite.benchmarks)
    assert any(b.name == "pressure_compact" for b in suite.benchmarks)


def test_builtin_benchmarks_include_sandbox_overhead_cases() -> None:
    suite = create_builtin_benchmarks()
    names = {bench.name for bench in suite.benchmarks}

    assert {
        "sandbox_setup",
        "sandbox_noop",
        "extract_cold",
        "extract_cached",
    }.issubset(names)


def test_builtin_quick_mode_avoids_stress_only_cases() -> None:
    suite = create_builtin_benchmarks()
    quick_names = {bench.name for bench in suite.select(mode=BenchmarkMode.QUICK)}

    assert "cli_scan" in quick_names
    assert "scanner_scan" in quick_names
    assert "formatters" in quick_names
    assert "container_models" in quick_names
    assert "except_cache" in quick_names
    assert "line_cache" in quick_names
    assert "literal_cache" in quick_names
    assert "sat_cache" in quick_names
    assert "unsat_cache" in quick_names
    assert "string_models" not in quick_names
    assert "constraint_hash" not in quick_names
    assert "detector_scan" not in quick_names
    assert "path_cap" not in quick_names
    assert "shadow_admit" not in quick_names
    assert "runtime_admit" not in quick_names
    assert "compact_admit" not in quick_names
    assert "preview_exec" not in quick_names
    assert "preview_unsat" not in quick_names
    assert "cegis_exact" not in quick_names
    assert "cegis_dedupe" not in quick_names
    assert "cegis_core" not in quick_names
    assert "pressure_compact" not in quick_names


def test_builtin_category_filter_includes_cases_outside_quick_mode() -> None:
    suite = create_builtin_benchmarks()
    sandbox_names = {
        bench.name for bench in suite.select(mode=None, category=BenchmarkCategory.SANDBOX)
    }

    assert {
        "sandbox_setup",
        "sandbox_noop",
        "extract_cold",
        "extract_cached",
    }.issubset(sandbox_names)


def test_builtin_category_filter_includes_model_and_reporting_cases() -> None:
    suite = create_builtin_benchmarks()
    model_names = {
        bench.name for bench in suite.select(mode=None, category=BenchmarkCategory.MODELS)
    }
    reporting_names = {
        bench.name for bench in suite.select(mode=None, category=BenchmarkCategory.REPORTING)
    }

    assert {"string_models", "container_models"}.issubset(model_names)
    assert reporting_names == {"formatters"}


def test_builtin_category_filter_includes_frontier_memory_cases() -> None:
    suite = create_builtin_benchmarks()
    memory_names = {
        bench.name for bench in suite.select(mode=None, category=BenchmarkCategory.MEMORY)
    }

    assert {
        "state_fork",
        "shadow_admit",
        "runtime_admit",
        "compact_admit",
        "preview_exec",
        "cegis_dedupe",
        "pressure_compact",
    }.issubset(memory_names)


def test_builtin_category_filter_includes_cegis_solver_preview_case() -> None:
    suite = create_builtin_benchmarks()
    solving_names = {
        bench.name for bench in suite.select(mode=None, category=BenchmarkCategory.SOLVING)
    }

    assert "preview_unsat" in solving_names
    assert "cegis_exact" in solving_names
    assert "cegis_core" in solving_names
    assert "literal_cache" in solving_names
    assert "sat_cache" in solving_names
    assert "unsat_cache" in solving_names


def test_builtin_category_filter_includes_path_explosion_cases() -> None:
    suite = create_builtin_benchmarks()
    path_names = {bench.name for bench in suite.select(mode=None, category=BenchmarkCategory.PATHS)}

    assert "path_cap" in path_names


def test_builtin_benchmarks_accept_legacy_case_aliases() -> None:
    suite = create_builtin_benchmarks()

    assert suite.select(mode=None, case_name="executor_core_function")[0].name == "exec_core"
    assert (
        suite.select(mode=None, case_name="frontier_runtime_cegis_core_reuse_pruning")[0].name
        == "cegis_core"
    )
