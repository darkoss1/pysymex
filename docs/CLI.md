# pysymex Command-Line Interface (CLI) Guide

Complete guide for using pysymex from the command line.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Commands Overview](#commands-overview)
4. [scan](#scan)
5. [analyze](#analyze)
6. [verify](#verify)
7. [concolic](#concolic)
8. [benchmark](#benchmark)
9. [Output Formats](#output-formats)
10. [check](#check)
11. [Examples](#examples)

---

## Quick Start

```bash
# Scan a single file
pysymex scan mycode.py

# Scan a directory recursively
pysymex scan src/ -r

# Analyze a specific function with typed arguments
pysymex analyze mycode.py -f risky_func --args x:int y:str

# Generate SARIF report for CI/CD
pysymex scan src/ -r --format sarif -o report.sarif

# Run benchmarks
pysymex benchmark --format markdown
```

---

## Installation

### From Source

```bash
git clone https://github.com/darkoss1/pysymex.git
cd pysymex
pip install -e .
```

### Requirements

- Python 3.11+
- z3-solver == 4.15.3.0
- pydantic >= 2.12.0
- immutables == 0.21
- rich >= 13.0.0

---

## Commands Overview

| Command | Description |
|---------|-------------|
| `scan` | Scan a file or directory for bugs |
| `analyze` | Symbolically analyze a specific function |
| `verify` | Verify function contracts |
| `concolic` | Generate test cases via concolic execution |
| `benchmark` | Run the benchmark suite |
| `check` | Run a CI-friendly severity-gated scan |

---

## scan

Scan a Python file or directory for bugs and vulnerabilities.

```bash
pysymex scan PATH [OPTIONS]
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `path` | (required) | File or directory to scan |
| `--mode {symbolic,static,pipeline}` | `symbolic` | Analysis mode |
| `--format {text,json,sarif,rich,html,markdown}` | `text` | Output format |
| `-o OUTPUT` | stdout | Write report to file |
| `-r` / `--recursive` | False | Scan directories recursively |
| `-v` / `--verbose` | False | Verbose output |
| `--stats` | False | Show detailed performance statistics |
| `--max-paths N` | 5000 | Max paths per function |
| `--timeout N` | 5 | Timeout per function in seconds |
| `--workers N` | 0 (auto) | Worker processes (0 = CPU count, 1 = sequential) |
| `--auto` | False | Auto-tune analysis configuration |
| `--no-cache` | False | Disable all caching for fresh analysis |
| `--max-iterations N` | 0 (auto) | Max iterations per function |
| `--reproduce` | False | Generate reproduction scripts for findings |
| `--visualize` | False | Show real-time progress visualization |
| `--async` | False | Use async scanner (TaskGroup-based concurrency) |
| `--trace` | False | Emit execution traces for symbolic runs |
| `--trace-output-dir DIR` | `.pysymex/traces` | Directory for trace JSONL files |
| `--trace-verbosity` | `delta_only` | Trace detail: `quiet`, `delta_only`, `full` |
| `--sandbox` / `--no-sandbox` | sandbox enabled | Compile scan targets through the sandbox bridge |
| `--deterministic` | False | Use deterministic exploration for reproducible runs |
| `--seed N` | 42 | Random seed for deterministic runs |
| `--no-chtd` | False | Disable CHTD pruning |
| `--no-acceleration` | False | Disable acceleration backend |

### Analysis Modes

| Mode | Description |
|------|-------------|
| `symbolic` | Full symbolic execution with Z3 (default) |
| `static` | Fast static analysis without SMT solving |
| `pipeline` | Combined static + symbolic pipeline |

### Examples

```bash
# Scan a single file
pysymex scan mycode.py

# Scan a directory recursively
pysymex scan src/ -r

# Static analysis mode (faster)
pysymex scan src/ --mode static

# Full pipeline mode
pysymex scan src/ --mode pipeline

# Generate SARIF report (GitHub Security tab compatible)
pysymex scan src/ -r --format sarif -o report.sarif

# JSON output
pysymex scan src/ --format json -o results.json

# Parallel workers
pysymex scan src/ --workers 4

# Fresh analysis (bypass caches)
pysymex scan src/ --no-cache

# Async scanner
pysymex scan src/ -r --async
```

---

## analyze

Perform symbolic execution on a specific function.

```bash
pysymex analyze FILE -f FUNCTION [OPTIONS]
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `file` | (required) | Python file to analyze |
| `-f` / `--function` | (required) | Function name to analyze |
| `--args NAME:TYPE...` | None | Symbolic arguments (e.g., `x:int y:str`) |
| `--format` | `text` | Output format: `text`, `json`, `sarif`, `html`, `markdown`, `rich` |
| `-o OUTPUT` | stdout | Write report to file |
| `--max-paths N` | 100000 | Max paths to explore |
| `--timeout N` | 60 | Timeout in seconds |
| `-v` / `--verbose` | False | Verbose output |
| `--stats` | False | Show detailed performance statistics |

### Supported Argument Types

| Type | Description |
|------|-------------|
| `int` | Symbolic integer |
| `str` | Symbolic string |
| `list` | Symbolic list |
| `bool` | Symbolic boolean |
| `dict` | Symbolic dictionary |

### Examples

```bash
# Analyze a function
pysymex analyze mycode.py -f risky_divide

# With typed symbolic arguments
pysymex analyze mycode.py -f process --args items:list index:int

# HTML report
pysymex analyze mycode.py -f check_input --format html -o report.html

# Markdown report
pysymex analyze mycode.py -f my_func --format markdown
```

---

## verify

Verify function contracts and postconditions.

```bash
pysymex verify FILE [OPTIONS]
```

---

## concolic

Generate test cases using concolic (concrete + symbolic) execution.

```bash
pysymex concolic FILE -f FUNCTION [OPTIONS]
```

### Examples

```bash
pysymex concolic mycode.py -f my_func -n 50
```

---

## benchmark

Run the built-in benchmark suite to measure engine performance.

```bash
pysymex benchmark [OPTIONS]
```

### Examples

```bash
# Run benchmarks, print table
pysymex benchmark

# Markdown output
pysymex benchmark --format markdown

# JSON output to file
pysymex benchmark --format json -o benchmarks/baseline.json

# Compare against a baseline
pysymex benchmark --baseline benchmarks/baseline.json

# Run one benchmark case
pysymex benchmark --case executor_core_function
```

---

## Output Formats

### text (default)

Human-readable output printed to stdout.

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ pysymex - formal verification report                                         │
╰──────────────────────────────────────────────────────────────────────────────╯

ISSUES FOUND (1)
────────────────────────────────────────────────────────────
╭─ [ DIVISION_BY_ZERO ] ───────────────────────────────────────────────────────╮
│  Location: mycode.py:12 in unsafe_divide()                                   │
│  Type:    DIVISION_BY_ZERO                                                   │
│  Error:    Division by zero: y can be 0                                      │
│  Trigger:  y = 0                                                             │
╰──────────────────────────────────────────────────────────────────────────────╯

SUMMARY
────────────────────────────────────────────────────────────
Paths explored:         1
Paths completed:        1
Instructions:           4
Execution time:     0.018s

Proven safe:            0
Issues found:           1
```

### json

Structured JSON suitable for programmatic processing.

### sarif

SARIF 2.1.0 format, compatible with GitHub Security tab and other SARIF viewers.

```bash
pysymex scan src/ -r --format sarif -o report.sarif
```

### rich / html / markdown

Available from the CLI formatters for scan, analyze, and verification-style output.

---

## check

Run CI-friendly checks across one or more files or directories.

```bash
pysymex check PATH [PATH ...] [OPTIONS]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `paths` | (required) | Files or directories to check |
| `--fail-on {low,medium,high,critical}` | `high` | Minimum severity that returns a non-zero exit |
| `--sarif PATH` | None | Write SARIF output |
| `-v` / `--verbose` | False | Verbose output |

---

## Examples

### Quick Project Scan

```bash
pysymex scan ./src -r --format sarif -o security.sarif
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  pysymex:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -e .
      - run: pysymex scan ./src -r --format sarif -o report.sarif
      - uses: actions/upload-artifact@v4
        with:
          name: sarif-report
          path: report.sarif
```

### Validation Workflow

Alpha 5 added both focused pytest coverage and the `experiments/runner.py` milestone
validation harness. Use focused pytest targets for regression checks, the experiment
runner for curated corpus validation, and `pysymex benchmark` for benchmark coverage.

```bash
uv run pytest tests/unit/scanner
uv run python experiments/runner.py
uv run pysymex benchmark --format markdown
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Issues found or error |

---

## See Also

- [API Reference](API.md) - Python API
- [Scanner Guide](SCANNER.md) - Scanner module API
- [Examples](../examples/) - Code examples
