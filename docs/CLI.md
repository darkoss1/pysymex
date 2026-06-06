# Command-Line Interface

The `pysymex` command is registered by `pyproject.toml` and implemented under `pysymex.cli`.
Command names and flags come from `pysymex.cli.parser`.

## Global Options

| Option | Meaning |
| --- | --- |
| `-V`, `--version` | Print the package version. |
| `--generate-completion {bash,zsh,fish}` | Generate a shell completion script. |
| `--quiet` | Suppress non-error diagnostics. |
| `--debug` | Enable debug diagnostics. |
| `--diagnostic-trace` | Enable trace diagnostics. |
| `--log-category NAME` | Enable a diagnostic category. May be passed multiple times. |
| `--log-jsonl PATH` | Write structured diagnostics to a JSONL file. |
| `--log-history N` | Retain a bounded in-memory diagnostic history for the run. |

## Commands

| Command | Purpose |
| --- | --- |
| `pysymex scan PATH` | Scan one file or directory for supported issue patterns. |
| `pysymex analyze FILE -f NAME` | Analyze one function from a file. |
| `pysymex verify FILE -f NAME` | Preview contract-aware verification for one function. |
| `pysymex benchmark` | Run built-in benchmark cases. |
| `pysymex check PATH...` | CI-oriented scan with severity-gated exit behavior and optional SARIF output. |

## `scan`

```bash
pysymex scan path/to/file.py
pysymex scan src/ -r --format sarif -o report.sarif
pysymex scan "src/**/*.py" --deterministic --seed 42
```

Important options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--format {text,json,sarif,rich,html,markdown}` | `text` | Output format. |
| `-o`, `--output PATH` | none | Write report to a file. |
| `-r`, `--recursive` | `False` | Scan directories recursively. |
| `-v`, `--verbose` | `False` | Verbose scan output. |
| `--stats` | `False` | Show performance statistics. |
| `--max-paths N` | `5000` | Maximum paths per function. |
| `--timeout SECONDS` | `10` | Timeout per function. |
| `--workers N` | `0` | Directory worker processes. `0` uses conservative auto mode; `1` is sequential. |
| `--auto` | `False` | Auto-tune analysis configuration. |
| `--no-cache` | `False` | Disable process-local, result, and solver caches for fresh analysis. |
| `--no-sandbox` | `False` | Compile target bytecode in-process instead of using sandboxed extraction. This is faster but bypasses the sandboxed bytecode extraction boundary. |
| `--max-iterations N` | `0` | Maximum iterations per function. `0` auto-calculates. |
| `--reproduce` | `False` | Generate reproduction scripts for findings when the formatter supports it. |
| `--visualize` | `False` | Use realtime progress visualization. |
| `--async` | `False` | Use the async scanner runner. |
| `--trace` | `False` | Emit execution traces. |
| `--trace-output-dir PATH` | `.pysymex/traces` | Trace output directory. |
| `--trace-verbosity {quiet,delta_only,full}` | `delta_only` | Trace detail level. |
| `--deterministic` | `False` | Use deterministic non-dynamic exploration for reproducible directory runs. |
| `--seed N` | `42` | Random seed for deterministic runs. |

Exit behavior visible in code:

- `0` when scan results contain no issues, no fatal errors, and no degraded analyses.
- `1` when issues are found, the scan target is missing, no file result is produced, report
  generation fails, any file has a fatal error, or any analysis records degraded passes.

## `analyze`

```bash
pysymex analyze src/example.py -f risky_divide --args x:int y:int
pysymex analyze src/example.py -f risky_divide --format json -o result.json
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `FILE` | required | Python file containing the function. |
| `-f`, `--function NAME` | required | Function to analyze. |
| `--args name:type ...` | none | Symbolic argument hints. |
| `--format {text,json,sarif,rich,html,markdown}` | `text` | Output format. |
| `-o`, `--output PATH` | none | Write report to a file. |
| `--max-paths N` | `100000` | Maximum execution paths. |
| `--timeout SECONDS` | `60` | Maximum analysis time. |
| `-v`, `--verbose` | `False` | Verbose output. |
| `--stats` | `False` | Show performance statistics. |

Exit behavior:

- `0` when the analyzed function returns an `ExecutionResult` with no issues.
- `1` when issues are found, the file is missing, or analysis raises a handled
  `ValueError`, `TypeError`, `SyntaxError`, or `OSError`.

## `verify`

```bash
pysymex verify src/contracts.py -f bounded_divide --args x:int y:int
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `FILE` | required | Python file containing contract-decorated code. |
| `-f`, `--function NAME` | parser default is all contracts | Current sandboxed command path requires this option. |
| `--args name:type ...` | none | Symbolic argument hints. |
| `--format {text,json,sarif,rich,html,markdown}` | `text` | Output format. |
| `-o`, `--output PATH` | none | Write report to a file. |
| `-v`, `--verbose` | `False` | Verbose output. |

The command emits a preview warning. Current sandboxed verify behavior requires `--function`; if it
is omitted, the command returns `1`.

Exit behavior:

- `0` when execution succeeds, no symbolic issues are found, no contract or arithmetic issues are
  found, and no degraded passes are recorded.
- `1` when the file is missing, `VerifiedExecutor` is unavailable, `--function` is omitted on the
  sandboxed path, execution fails, findings are emitted, degraded passes are recorded, or command
  handling raises an exception.

## `benchmark`

```bash
pysymex benchmark
pysymex benchmark --mode quick --format markdown -o benchmark.md
pysymex benchmark --mode all --format markdown -o benchmark.md
pysymex benchmark --category solving --iterations 3 --warmup 1
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--format {text,json,markdown}` | `text` | Output format. |
| `--mode {quick,full,stress,all}` | auto | Benchmark scope. `all` runs every registered case. |
| `--category CATEGORY` | none | Run one benchmark category. |
| `-o`, `--output PATH` | none | Write results to a file. |
| `--baseline PATH` | none | Compare against a baseline file. |
| `-n`, `--iterations N` | `1` | Iterations per benchmark. |
| `--warmup N` | `1` | Warm-up iterations. |
| `--case NAME` | none | Run one benchmark case. |
| `--list` | `False` | List benchmark cases and exit. |
| `--threshold PERCENT` | `10.0` | Regression threshold when using `--baseline`. |

Exit behavior is delegated to `pysymex.benchmarks.run_benchmarks`. The command returns `1` when the
runner raises an exception or when the benchmark runner reports a regression/failure.
Unfiltered runs default to quick mode; focused category/case filters include all matching cases
unless `--mode` is supplied. Legacy long case names remain accepted by `--case` as aliases.

## `check`

```bash
pysymex check src/ --fail-on high --sarif report.sarif
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `PATH...` | required | Files or directories to check. |
| `--fail-on {low,medium,high,critical}` | `high` | Minimum severity that causes a non-zero exit. |
| `--sarif PATH` | none | Write SARIF output. |
| `-v`, `--verbose` | `False` | Verbose output. |

`check` delegates to `pysymex.ci.run_ci_check`. It is intended for CI, so its exit code reflects
the configured severity threshold rather than just process success.

## Output Semantics

Output format does not change finding certainty. Text, rich, JSON, SARIF, HTML, and Markdown are
presentation formats over the same issue, error, degraded-pass, and solver-stat data.
