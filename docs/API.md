# Python API

The public Python API is exposed through `pysymex` and `pysymex.api`. Anything under deeper
packages such as `pysymex.execution`, `pysymex.core`, `pysymex.analysis`, `pysymex.scanner`, or
`pysymex.sandbox` is implementation-owned unless this page names it as a public entrypoint.

## Main Entrypoints

| Entrypoint | Async | Returns | Notes |
| --- | --- | --- | --- |
| `analyze(func, symbolic_args=None, **kwargs)` | yes | `ExecutionResult` | Analyze a Python callable. Alias: `check`. |
| `analyze_code(code, symbolic_vars=None, **kwargs)` | yes | `ExecutionResult` | Compile and analyze a source string. |
| `analyze_file(filepath, function_name, symbolic_args=None, **kwargs)` | yes | `ExecutionResult` | Load one function from a Python file. Alias: `scan`. |
| `scan_directory(dir_path, pattern="**/*.py", ...)` | yes | `list[ScanResult]` | Async directory scanner facade. |
| `scan_file(file_path, ...)` | no | `ScanResult` | Synchronous single-file scanner facade. |
| `quick_check(func)` | no | `list[Issue]` | Synchronous convenience check with smaller limits. |
| `check_division_by_zero(func)` | no | `list[Issue]` | Focused division-by-zero helper. |
| `check_assertions(func)` | no | `list[Issue]` | Focused assertion helper. |
| `check_index_errors(func)` | no | `list[Issue]` | Focused index-error helper. |
| `verify(func, symbolic_args=None, **overrides)` | no | `VerifiedExecutionResult` | Contract-aware verified execution wrapper. Experimental. |
| `check_contracts(func, symbolic_args=None)` | no | `list[ContractIssue]` | Contract-only convenience helper. Experimental. |
| `check_arithmetic(func, symbolic_args=None)` | no | `list[ArithmeticIssue]` | Opt-in bounded arithmetic and division-safety helper. |
| `prove_termination(func, symbolic_args=None)` | no | `TerminationProof` | Public wrapper currently returns `UNKNOWN`. |

`Z3_AVAILABLE` is also exported at package level. Most runtime exports require Z3; non-Z3 exports
include configuration and logging helpers.

## Minimal Async Example

```python
import asyncio

from pysymex import analyze


def risky_divide(x: int, y: int) -> int:
    return x // y


result = asyncio.run(analyze(risky_divide, {"x": "int", "y": "int"}))

for issue in result.issues:
    print(issue.kind.name)
    print(issue.message)
    print(issue.get_counterexample())
```

`analyze`, `analyze_code`, `analyze_file`, and top-level `scan_directory` are async. Use
`asyncio.run(...)` in a synchronous script or `await` them inside an event loop.

## Analyze Configuration

`analyze` accepts either an `ExecutionConfig` or keyword overrides. Common overrides:

| Option | Default in `analyze` | Meaning |
| --- | --- | --- |
| `max_paths` | `1000` | Maximum execution paths to explore. |
| `max_depth` | `100` | Maximum execution depth. |
| `max_iterations` | `10000` | Maximum VM iterations. |
| `timeout` | `60.0` | Analysis timeout in seconds. |
| `strategy` | `ExplorationStrategy.ADAPTIVE` | Path exploration strategy. |
| `detect_division_by_zero` | `True` | Enable division-by-zero detection. |
| `detect_assertion_errors` | `True` | Enable assertion detection. |
| `detect_index_errors` | `True` | Enable index-error detection. |
| `detect_type_errors` | `True` | Enable type-error detection. |
| `detect_overflow` | `False` | Enable bounded-overflow diagnostics. Python ints are otherwise unbounded. |

`analyze_code` uses larger defaults internally: `max_paths=10000`, `max_depth=1000`,
`max_iterations=100000`, and `timeout_seconds=300.0`.

## File and Directory Scanning

```python
from pysymex import scan_file

result = scan_file("src/example.py", max_paths=5000, timeout=10)
print(result.to_dict())
```

`scan_file` is the synchronous single-file scanner from `pysymex.api.scanning`. It returns a
`ScanResult`, not an `ExecutionResult`.

For async directory scans:

```python
import asyncio

from pysymex import scan_directory


results = asyncio.run(scan_directory("src", pattern="**/*.py", max_paths=100, timeout=30.0))
```

## Result Objects

| Result | Important fields |
| --- | --- |
| `ExecutionResult` | `issues`, `paths_explored`, `paths_completed`, `paths_pruned`, `coverage`, `total_time_seconds`, `solver_time_seconds`, `solver_stats`, `degraded_passes`. |
| `ScanResult` | `file_path`, `issues`, `code_objects`, `paths_explored`, `elapsed_time`, `avg_memory_mb`, `error`, `degraded_passes`, `solver_stats`. |
| `VerifiedExecutionResult` | `issues`, `contract_issues`, `arithmetic_issues`, `termination_proof`, `contracts_checked`, `contracts_verified`, `contracts_violated`, `degraded_passes`. |

Use `ExecutionResult.has_issues()`, `ExecutionResult.get_issues_by_kind(kind)`,
`ExecutionResult.to_dict()`, or `ExecutionResult.to_sarif()` for common result handling.

## Issues

`Issue` records are immutable detector findings. Important fields include `kind`, `message`,
`constraints`, `model`, bytecode `pc`, source location fields, `counterexample`, `confidence`,
`severity`, and optional `suppression_reason`.

Use `issue.get_counterexample()` to extract witness values when a model is available.

## Formatting and Logging

| Entrypoint | Purpose |
| --- | --- |
| `format_issues(issues, format_type="text")` | Format issue lists as text or JSON. |
| `format_result(result, format_type)` | Format an execution result through the API formatting facade. |
| `configure_logging(...)` | Configure PySyMex diagnostics. |
| `get_logger(...)` | Get a PySyMex logger. |

Library code should use `pysymex.logger` diagnostics rather than `print()`.

## Experimental and Internal APIs

These exports are available but should be treated carefully:

- `VerifiedExecutor`, `VerifiedExecutionConfig`, `VerifiedExecutionResult`, and verification
  helpers are contract-aware execution APIs still marked experimental in CLI behavior.
- `SymbolicExecutor`, `VMState`, `SymbolicValue`, `SymbolicString`, `SymbolicList`,
  `SymbolicDict`, `SymbolicObject`, `SymbolicNone`, and `IncrementalSolver` are useful for tests
  and advanced work, but they expose engine internals.
- Deeper package imports may change when architecture owners move. Prefer top-level `pysymex` or
  `pysymex.api` imports for user code.

## Result Semantics

An empty issue list is not a proof of full program safety. It means no definite issue was emitted
for the explored supported paths. Check `degraded_passes`, scanner `error`, solver stats, and
reported unsupported or blocked behavior before interpreting a result.
