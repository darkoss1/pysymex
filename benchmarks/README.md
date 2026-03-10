# Benchmark Artifacts (`0.4.0-alpha`)

This folder contains reproducible local benchmark artifacts used for the
`v0.4.0-alpha` release gate.

## Files

- `v0.3.0a0-baseline.json`: Baseline benchmark run from commit `34fd97d`
  (`Release v0.3.0 alpha`), generated on the same host/interpreter.
- `v0.4.0a0-current.json`: Current benchmark run from the working tree.
- `comparison-v0.3.0a0-v0.4.0a0.md`: Comparison output produced by
  `pysymex benchmark --baseline ...`.

## Generation Procedure

1. Baseline:
   - Checked out commit `34fd97d` in a detached worktree.
   - Ran benchmark suite for `iterations=3` (warmup defaults to `1` in suite).
2. Current:
   - Ran current benchmark suite for `iterations=3`.
3. Comparison:
   - Ran current suite with `--baseline benchmarks/v0.3.0a0-baseline.json`.

## Environment Metadata

- Python: `3.13.11`
- Platform: `Windows-11-10.0.26200-SP0`
- Solver dependency: `z3-solver 4.15.8.0`

## Caveats

- The `v0.3.0a0` suite includes only three benchmark cases
  (`simple_arithmetic`, `branching`, `loop_unrolling`).
- The comparison report evaluates only overlapping benchmark names.
- Results are local-machine measurements and should be treated as directional.
