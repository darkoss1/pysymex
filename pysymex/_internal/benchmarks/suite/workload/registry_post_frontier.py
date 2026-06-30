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

"""Built-in benchmark metadata registered after runtime frontier cases."""

from __future__ import annotations

from pysymex._internal.benchmarks.suite.types import BenchmarkCategory
from pysymex._internal.benchmarks.suite.workload.analysis import (
    bench_contract_verification,
    bench_runtime_detector_scan,
)
from pysymex._internal.benchmarks.suite.workload.models import (
    bench_container_model_dispatch,
    bench_scalar_carrier_construction,
    bench_string_model_dispatch,
)
from pysymex._internal.benchmarks.suite.workload.registry_specs import (
    FULL_STRESS,
    QUICK_FULL_STRESS,
    STRESS_ONLY,
    BenchmarkSpec,
)
from pysymex._internal.benchmarks.suite.workload.reporting import bench_reporting_formatters
from pysymex._internal.benchmarks.suite.workload.sandbox import (
    bench_sandbox_extract_module_cached,
    bench_sandbox_extract_module_cold,
    bench_sandbox_strong_execute_noop,
    bench_sandbox_strong_setup,
)
from pysymex._internal.benchmarks.suite.workload.solver import bench_constraint_hashing

POST_FRONTIER_BENCHMARK_SPECS = (
    BenchmarkSpec(
        name="scalar_carriers",
        func=bench_scalar_carrier_construction,
        category=BenchmarkCategory.MODELS,
        description="Isolated scalar and string carrier construction over cached Z3 literals",
        modes=QUICK_FULL_STRESS,
        tags=("models", "types", "cache"),
    ),
    BenchmarkSpec(
        name="string_models",
        func=bench_string_model_dispatch,
        category=BenchmarkCategory.MODELS,
        description="Symbolic string startswith, endswith, count and rfind models",
        modes=FULL_STRESS,
        tags=("models", "strings", "symbolic-executor"),
    ),
    BenchmarkSpec(
        name="container_models",
        func=bench_container_model_dispatch,
        category=BenchmarkCategory.MODELS,
        description="List, tuple, membership, len, sum, min and indexing model dispatch",
        modes=QUICK_FULL_STRESS,
        tags=("models", "containers", "builtins"),
    ),
    BenchmarkSpec(
        name="formatters",
        func=bench_reporting_formatters,
        category=BenchmarkCategory.REPORTING,
        description="JSON, Markdown, HTML and SARIF scan report formatting overhead",
        modes=QUICK_FULL_STRESS,
        tags=("reporting", "formatters"),
    ),
    BenchmarkSpec(
        name="sandbox_setup",
        func=bench_sandbox_strong_setup,
        category=BenchmarkCategory.SANDBOX,
        description="Strong sandbox context setup and cleanup overhead",
        modes=FULL_STRESS,
        tags=("sandbox", "setup"),
        stability="platform-dependent",
    ),
    BenchmarkSpec(
        name="sandbox_noop",
        func=bench_sandbox_strong_execute_noop,
        category=BenchmarkCategory.SANDBOX,
        description="Strong sandbox setup plus tiny code execution overhead",
        modes=FULL_STRESS,
        tags=("sandbox", "execution"),
        stability="platform-dependent",
    ),
    BenchmarkSpec(
        name="extract_cold",
        func=bench_sandbox_extract_module_cold,
        category=BenchmarkCategory.SANDBOX,
        description="Cold sandbox bridge module extraction overhead",
        modes=FULL_STRESS,
        tags=("sandbox", "module-extraction"),
        stability="platform-dependent",
    ),
    BenchmarkSpec(
        name="extract_cached",
        func=bench_sandbox_extract_module_cached,
        category=BenchmarkCategory.SANDBOX,
        description="Process-local sandbox bridge module extraction cache-hit overhead",
        modes=FULL_STRESS,
        tags=("sandbox", "module-extraction", "cache"),
        stability="platform-dependent",
    ),
    BenchmarkSpec(
        name="constraint_hash",
        func=bench_constraint_hashing,
        category=BenchmarkCategory.SOLVING,
        description="Structural constraint hashing performance",
        modes=STRESS_ONLY,
        tags=("solver", "hashing", "stress"),
    ),
    BenchmarkSpec(
        name="detector_scan",
        func=bench_runtime_detector_scan,
        category=BenchmarkCategory.ANALYSIS,
        description="Scanner-driven runtime detector workload with guarded controls",
        modes=FULL_STRESS,
        tags=("analysis", "detectors", "scanner"),
    ),
    BenchmarkSpec(
        name="contracts",
        func=bench_contract_verification,
        category=BenchmarkCategory.ANALYSIS,
        description="ContractVerifier proving preconditions, postconditions and loop invariants",
        modes=FULL_STRESS,
        tags=("analysis", "contracts"),
    ),
)
