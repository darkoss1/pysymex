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
10. [Examples](#examples)

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
- z3-solver >= 4.12.0
- pydantic >= 2.0.0

---

## Commands Overview

| Command | Description |
|---------|-------------|
| `scan` | Scan a file or directory for bugs |
| `analyze` | Symbolically analyze a specific function |
| `verify` | Verify function contracts |
| `concolic` | Generate test cases via concolic execution |
| `benchmark` | Run the benchmark suite |

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
| `--format {text,json,sarif}` | `text` | Output format |
| `-o OUTPUT` | stdout | Write report to file |
| `-r` / `--recursive` | False | Scan directories recursively |
| `-v` / `--verbose` | False | Verbose output |
| `--max-paths N` | 200 | Max paths per function |
| `--timeout N` | 30 | Timeout per function in seconds |
| `--workers N` | 0 (auto) | Worker processes (0 = CPU count, 1 = sequential) |
| `--watch` | False | Re-scan on file changes |
| `--auto` | False | Auto-tune analysis configuration |
| `--no-cache` | False | Disable all caching for fresh analysis |
| `--max-iterations N` | 0 (auto) | Max iterations per function |
| `--reproduce` | False | Generate reproduction scripts for findings |
| `--visualize` | False | Show real-time progress visualization |
| `--async` | False | Use async scanner (TaskGroup-based concurrency) |
| `--trace` | False | Emit execution traces for symbolic runs |
| `--trace-output-dir DIR` | `.pysymex/traces` | Directory for trace JSONL files |
| `--trace-verbosity` | `delta_only` | Trace detail: `quiet`, `delta_only`, `full` |

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

# Watch mode — re-scan on file changes
pysymex scan . --watch

# Parallel workers
pysymex scan src/ --workers 4

# Fresh analysis (bypass caches)
pysymex scan src/ --no-cache
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
| `--format` | `text` | Output format: `text`, `json`, `sarif`, `html`, `markdown` |
| `-o OUTPUT` | stdout | Write report to file |
| `--max-paths N` | 200 | Max paths to explore |
| `--timeout N` | 30 | Timeout in seconds |
| `-v` / `--verbose` | False | Verbose output |

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
```

---

## Output Formats

### text (default)

Human-readable output printed to stdout.

```
══════════════════════════════════════════════════════════════════════
 PySyMex — Formal Verification Report
══════════════════════════════════════════════════════════════════════

CRASHES PROVEN POSSIBLE (Z3 found counterexamples):
──────────────────────────────────────────────────────────────────────

  [DIVISION BY ZERO]
    mycode.py:12 in unsafe_divide()
       Division by zero: y can be 0 in //
       Crash when: y=0
```

### json

Structured JSON suitable for programmatic processing.

### sarif

SARIF 2.1.0 format, compatible with GitHub Security tab and other SARIF viewers.

```bash
pysymex scan src/ -r --format sarif -o report.sarif
```

### html / markdown

Available for the `analyze` subcommand only.

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

### Watch Mode During Development

```bash
# Keep scanner running while editing
pysymex scan . --watch
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
