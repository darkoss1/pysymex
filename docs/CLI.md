# Command-Line Interface

The `pysymex` command is registered by `pyproject.toml` and implemented under `pysymex._internal.cli`.
Global options come from `pysymex._internal.cli.parser`. First-class command names, parser registration
order, and runtime dispatch are owned by `pysymex._internal.cli.commands.registry`; each command module under
`pysymex._internal.cli.commands` owns its own flags and handler.

Run `pysymex <command> --help` for command-specific options. Running `pysymex` without a command is
an invalid invocation and exits through `argparse` with status `2`.

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
| `--log-history N` | Retain a bounded in-memory diagnostic history for the run. `N` must be `0` or greater. |

## Parser Validation

Parser-level invalid invocations exit through `argparse` with status `2`, before target loading or
symbolic execution starts.

Numeric limits reject impossible values at parse time:

- Positive values are required for path limits, timeouts, benchmark iterations, and
  `trace-analyze --head/--tail`.
- Zero-or-greater values are accepted for worker counts, auto iteration limits, warmup counts,
  regression thresholds, diagnostic history length, trace IDs, trace ranges, source lines,
  latencies, and constraint counts.

Symbolic arguments for `contracts` must use `NAME:TYPE`. `NAME` must be a Python
identifier that is not a keyword. `TYPE` must be non-empty; the type string is passed to the
symbolic input factory, so forms such as `optional:int` remain valid. Duplicate symbolic argument
names are rejected by command handling instead of silently overwriting earlier values.

## Commands

| Command | Purpose |
| --- | --- |
| `pysymex scan PATH` | Scan one file or directory for supported issue patterns. |
| `pysymex contracts FILE -f NAME` | Preview contract-aware verification for one function. |
| `pysymex benchmark` | Run built-in benchmark cases. |
| `pysymex trace-analyze TRACE_FILE` | Filter and summarize JSONL execution traces. |

## `scan`

```bash
pysymex scan path/to/file.py
pysymex scan src/ --format sarif -o report.sarif
pysymex scan "src/**/*.py" --format json
```

Important options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--format {text,json,sarif,rich,html,markdown}` | `text` | Output format. |
| `-o`, `--output PATH` | none | Write report to a file. |
| `-v`, `--verbose` | `False` | Verbose scan output. |
| `--stats` | `False` | Show performance statistics. |
| `--profile` | `False` | Enable developer profiling. This also enables stats and execution traces, writes cProfile `.pstats` plus JSON summary artifacts, and prints bottleneck diagnostics after the scan report. |
| `--profile-output-dir PATH` | `.pysymex/profiles` | Directory where `--profile` writes profiling artifacts. |
| `--profile-baseline PROFILE.json` | none | Enable profiling and compare the new metrics with a prior profile JSON artifact. |
| `--max-paths N` | automatic | Optional paths per function. `N` must be greater than `0`. |
| `--max-depth N` | automatic | Optional symbolic step depth per path. `N` must be greater than `0`. |
| `--timeout SECONDS` | automatic | Optional timeout per function. `SECONDS` must be greater than `0`. |
| `--workers N` | `0` | Directory worker processes. `N` must be `0` or greater; `0` uses conservative auto mode and `1` is sequential. |
| `--auto` | `False` | Auto-tune analysis configuration. |
| `--no-cache` | `False` | Disable process-local, result, and solver caches for fresh analysis. |
| `--no-sandbox` | `False` | Compile target bytecode in-process instead of using sandboxed extraction. This is faster but bypasses the sandboxed bytecode extraction boundary. |
| `--max-iterations N` | automatic | Optional VM iterations per function. Positive values cap iterations explicitly. |
| `--reproduce` | `False` | Generate reproduction scripts for findings when the formatter supports it. |
| `--visualize` | `False` | Use realtime progress visualization. |
| `--trace` | `False` | Emit execution traces. |
| `--trace-output-dir PATH` | `.pysymex/traces` | Trace output directory. |
| `--trace-verbosity {quiet,delta_only,full}` | `delta_only` | Trace detail level. |

`--profile` is a diagnostic mode. It does not change path feasibility, solver outcomes, detector
classification, or issue certainty. Its cProfile data covers work in the CLI process; directory
scans that use worker processes are still summarized through per-file scan results and stats
counters, while worker-internal Python call stacks are not captured in the parent `.pstats` file.

The versioned JSON summary records the Python/platform context, bounded scan configuration,
measured scan and CLI wall times, path throughput, SAT/UNSAT/UNKNOWN counts, solver time, solver
result-cache reuse, detector-feasibility cache reuse, Z3-AST translation reuse, memory, degraded
labels, exclusive time by subsystem phase, cumulative and self-time hotspots, and raw artifact
paths. Runtime, dependency, target, and engine frames are classified separately so Python builtins
and `.venv` modules do not appear as engine-owned hotspots.

`--profile-baseline` uses a 5% relative noise floor for continuous metrics and exact comparison for
unknown/degraded counts. Directional labels are emitted only when schema and scan configuration
match. Schema or configuration differences remain visible and downgrade deltas to informational
changes rather than claiming an improvement or regression. cProfile adds measurement overhead, so
compare runs made with equivalent profile settings; use the unprofiled benchmark command for
release-grade wall-time claims.

Exit behavior visible in code:

- `0` when scan results contain no issues, no fatal errors, and no degraded analyses.
- `1` when issues are found, the scan target is missing, no file result is produced, report
  generation fails, any file has a fatal error, or any analysis records degraded passes.



## `contracts`

```bash
pysymex contracts src/contracts.py -f bounded_divide --args x:int y:int
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `FILE` | required | Python file containing contract-decorated code. |
| `-f`, `--function NAME` | required | Function to verify. Current sandboxed CLI behavior verifies one selected function. |
| `--args NAME:TYPE ...` | none | Symbolic argument hints. |
| `--format {text,json,sarif,rich,html,markdown}` | `text` | Output format. |
| `-o`, `--output PATH` | none | Write report to a file. |
| `-v`, `--verbose` | `False` | Verbose output. |

The command emits a preview warning. The parser requires `--function`; direct handler calls without
a selected function still fail closed instead of host-executing a module to discover all contracts.

Exit behavior:

- `0` when execution succeeds, no symbolic issues are found, no contract or arithmetic issues are
  found, and no degraded passes are recorded.
- `1` when the file is missing, `VerifiedExecutor` is unavailable, `--function` is omitted on the
  sandboxed path, execution fails, findings are emitted, degraded passes are recorded, or command
  handling raises an exception.
- `2` for parser-level invalid invocation, such as omitting the required `--function` flag.

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
| `-n`, `--iterations N` | `1` | Iterations per benchmark. `N` must be greater than `0`. |
| `--warmup N` | `1` | Warm-up iterations. `N` must be `0` or greater. |
| `--case NAME` | none | Run one benchmark case. |
| `--list` | `False` | List benchmark cases and exit. |
| `--threshold PERCENT` | `10.0` | Regression threshold when using `--baseline`. `PERCENT` must be `0` or greater. |

Exit behavior is delegated to `pysymex._internal.benchmarks.run_benchmarks`. The command returns `1` when the
runner raises an exception or when the benchmark runner reports a regression/failure.
Unfiltered runs default to quick mode; focused category/case filters include all matching cases
unless `--mode` is supplied. `--case` accepts the current names shown by `--list`.

## `trace-analyze`

```bash
pysymex trace-analyze trace.jsonl --format summary
pysymex trace-analyze trace.jsonl --event-type issue --count
pysymex trace-analyze trace.jsonl --path-id 42 --format pretty
```

Important options:

| Option | Default | Meaning |
| --- | --- | --- |
| `TRACE_FILE` | `-` | JSONL trace file, or stdin when omitted. |
| `--ai-manual` | `False` | Print the trace-analyzer reference manual and exit. |
| `--event-type NAME` | none | Keep only matching trace event types. May be passed repeatedly. |
| `--format {jsonl,pretty,summary}` | `jsonl` | Output shape for matching events. |
| `--fields name,...` | none | Emit only selected fields as JSON. |
| `--head N` | none | Stop after the first `N` matching events. `N` must be greater than `0`. |
| `--tail N` | none | Print the last `N` matching events. `N` must be greater than `0`. |
| `--count` | `False` | Print only the match count. |

Exit behavior:

- `0` when the trace is read and filtered successfully, including broken-pipe termination.
- `1` when the trace input file does not exist.
- `130` when interrupted by the user.

## Output Semantics

Output format does not change finding certainty. Text, rich, JSON, SARIF, HTML, and Markdown are
presentation formats over the same issue, error, degraded-pass, and solver-stat data.
