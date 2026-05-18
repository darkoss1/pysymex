# Benchmark Artifacts

This folder contains local benchmark artifacts and command examples for the current
benchmark suite.

## Files

- `v0.1.0a0-results.md`: Benchmark results from the `v0.1.0a0` release.
- `v0.1.0a4-results.md`: Benchmark results from the `v0.1.0a4` release.
- `v0.1.0a5-results.md`: Benchmark results from the `v0.1.0a5` release.

## Running Benchmarks

```bash
# Run the benchmark suite and print a table
pysymex benchmark

# Markdown output
pysymex benchmark --format markdown

# JSON output (for use as a new baseline)
pysymex benchmark --format json -o benchmarks/baseline.json

# Compare current results against baseline
pysymex benchmark --baseline benchmarks/baseline.json

# Run one built-in benchmark case
pysymex benchmark --case executor_core_function
```

## Environment Metadata

- Python: `3.13.11`
- Platform: `Windows-11-10.0.26200-SP0`
- Solver dependency: `z3-solver 4.15.8.0`

## Notes

- Results are local-machine measurements and should be treated as directional.
- The `incremental_solver` and `constraint_hashing` benchmarks are intentionally slow —
  they test Z3 under heavy constraint load. This is expected for an SMT-based verifier.
- Current built-in workloads include engine-level execution, branch-heavy execution,
  arithmetic, path exploration, linear constraints, incremental solving, state forking,
  constraint hashing, concurrency, and contract verification.
- Benchmark categories include OPCODES, PATHS, SOLVING, MEMORY, CONCURRENCY,
  END_TO_END, and ANALYSIS.
