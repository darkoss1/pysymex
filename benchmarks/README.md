# Benchmark Artifacts (`v0.1.0a1`)

This folder contains reproducible local benchmark artifacts for the `v0.1.0a1` release.

## Files

- `baseline.json`: Baseline benchmark run used for performance regression checks.
- `v0.1.0a0-results.md`: Benchmark results from the `v0.1.0a0` release.
- `comparison-v0.3.0a0-v0.4.0a0.md`: Historical comparison from pre-release development
  (internal versions only, kept for reference).

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
```

## Environment Metadata

- Python: `3.13.11`
- Platform: `Windows-11-10.0.26200-SP0`
- Solver dependency: `z3-solver 4.15.8.0`

## Notes

- Results are local-machine measurements and should be treated as directional.
- The `incremental_solver` and `constraint_hashing` benchmarks are intentionally slow —
  they test Z3 under heavy constraint load. This is expected for an SMT-based verifier.
- Benchmark categories: OPCODES, PATHS, SOLVING, MEMORY, CONCURRENCY.
