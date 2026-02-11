# PySpectre Command-Line Interface (CLI) Guide

Complete guide for using PySpectre from the command line.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Scanner Commands](#scanner-commands)
5. [Configuration Options](#configuration-options)
6. [Output Formats](#output-formats)
7. [Examples](#examples)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Scan a single file
python -m pyspectre.scanner --dir myfile.py

# Scan a directory
python -m pyspectre.scanner --dir ./src

# Watch mode (continuous scanning)
python -m pyspectre.scanner --dir ./src --watch

# Use the standalone scanner
python auto_scanner.py --dir ./src
```

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/darkoss1/pyspecter.git
cd pyspecter

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -e .
```

### Requirements

- Python 3.10, 3.11, 3.12, or 3.13
- z3-solver

---

## Basic Usage

### Module Scanner

The primary way to use PySpectre CLI:

```bash
python -m pyspectre.scanner [OPTIONS]
```

### Standalone Scanner

The `auto_scanner.py` file can be copied to any project:

```bash
python auto_scanner.py [OPTIONS]
```

---

## Scanner Commands

### Command-Line Arguments

| Argument | Short | Type | Default | Description |
|----------|-------|------|---------|-------------|
| `--dir` | `-d` | PATH | `.` | Directory to scan |
| `--log` | `-l` | FILE | `scan_log_TIMESTAMP.json` | Log file path |
| `--watch` | `-w` | FLAG | False | Enable watch mode |
| `--recursive` | `-r` | FLAG | True | Scan subdirectories |

### Examples

#### Scan Current Directory
```bash
python -m pyspectre.scanner
```

#### Scan Specific Directory
```bash
python -m pyspectre.scanner --dir ./src
python -m pyspectre.scanner -d C:\projects\myapp
```

#### Custom Log File
```bash
python -m pyspectre.scanner --dir ./src --log results.json
python -m pyspectre.scanner -d ./src -l ./reports/scan.json
```

#### Watch Mode (Continuous)
```bash
python -m pyspectre.scanner --dir ./src --watch
python -m pyspectre.scanner -d ./src -w
```
Press `Ctrl+C` to stop watching and see the summary.

#### Non-Recursive Scan
```bash
python -m pyspectre.scanner --dir ./src --recursive=false
```

---

## Configuration Options

### Execution Configuration

PySpectre uses these default settings (customizable via Python API):

| Setting | Default | Description |
|---------|---------|-------------|
| `max_paths` | 100 | Maximum paths to explore per function |
| `max_depth` | 50 | Maximum recursion depth |
| `max_iterations` | 5000 | Maximum iterations per function |
| `timeout_seconds` | 30.0 | Timeout per file |

### Config File (pyspectre.toml)

Create a `pyspectre.toml` file in your project root:

```toml
[execution]
max_paths = 100
max_depth = 50
max_iterations = 5000
timeout_seconds = 30.0

[detectors]
division_by_zero = true
assertion_errors = true
index_errors = true
type_errors = true
null_dereference = true
resource_leaks = true

[output]
format = "text"  # text, json, html
verbose = false
```

---

## Output Formats

### Console Output

```
======================================================================
🔍 Scanning: ./src/utils.py
======================================================================

⚠️  Found 2 potential issues:

   • [DIVISION_BY_ZERO] Division by zero possible (Line 15)
       └─ y = 0
   • [INDEX_ERROR] Index may be out of bounds (Line 23)
       └─ idx = -5

   📊 Stats: 5 code objects | 42 paths explored
```

### JSON Log Output

```json
{
  "session_start": "2026-01-17T12:00:00.000000",
  "last_update": "2026-01-17T12:01:30.000000",
  "total_files": 10,
  "total_issues": 5,
  "scans": [
    {
      "file": "./src/utils.py",
      "timestamp": "2026-01-17T12:00:05.000000",
      "issues": [
        {
          "kind": "DIVISION_BY_ZERO",
          "message": "Division by zero possible",
          "line": 15,
          "pc": 24,
          "counterexample": {"y": "0"}
        }
      ],
      "code_objects": 5,
      "paths_explored": 42,
      "error": null
    }
  ]
}
```

### Session Summary

```
======================================================================
📋 SESSION SUMMARY
======================================================================

   Files scanned:     10
   Files with issues: 3
   Files clean:       6
   Files with errors: 1
   
   Total issues:      5

   Issue breakdown:
      DIVISION_BY_ZERO            2 ██
      INDEX_ERROR                 2 ██
      NULL_DEREFERENCE            1 █

   📁 Log saved to: scan_log_20260117_120000.json
======================================================================
```

---

## Examples

### Example 1: Quick Project Scan

Scan a Python project and save results:

```bash
# Navigate to project
cd C:\projects\myapp

# Run scan
python -m pyspectre.scanner --dir . --log security_scan.json

# View results in JSON
type security_scan.json
```

### Example 2: CI/CD Integration

Add to your CI pipeline:

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  pyspectre:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install pyspectre
      - run: python -m pyspectre.scanner --dir ./src --log scan.json
      - uses: actions/upload-artifact@v4
        with:
          name: scan-results
          path: scan.json
```

### Example 3: Pre-Commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
python -m pyspectre.scanner --dir . > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "PySpectre found potential issues. Run: python -m pyspectre.scanner"
    exit 1
fi
```

### Example 4: Watch During Development

Keep scanner running while developing:

```bash
# Terminal 1: Start watch mode
python -m pyspectre.scanner --dir ./src --watch

# Terminal 2: Make code changes
# Scanner will automatically re-analyze modified files
```

---

## Issue Types Detected

| Issue Kind | Description | Example |
|------------|-------------|---------|
| `DIVISION_BY_ZERO` | Division where denominator can be 0 | `x / y` where y=0 |
| `INDEX_ERROR` | List/array access out of bounds | `arr[i]` where i=-1 |
| `NULL_DEREFERENCE` | Accessing attribute of None | `obj.method()` where obj=None |
| `TYPE_ERROR` | Type mismatch in operations | `"str" + 5` |
| `ASSERTION_ERROR` | Assert can fail | `assert x > 0` where x=0 |
| `KEY_ERROR` | Dictionary key not found | `d[key]` where key missing |
| `RESOURCE_LEAK` | Unclosed file/resource | `open(f)` without close |
| `FORMAT_STRING_ERROR` | String formatting issues | `"{} {}".format(x)` |

---

## Troubleshooting

### Common Issues

#### "Module not found" Error
```bash
# Ensure you're in the right environment
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/macOS

# Install PySpectre
pip install -e .
```

#### Slow Analysis
```bash
# Reduce analysis depth in pyspectre.toml
[execution]
max_paths = 50
max_iterations = 2000
timeout_seconds = 15.0
```

#### Out of Memory
```bash
# Scan fewer files at once
python -m pyspectre.scanner --dir ./src/module1 --log part1.json
python -m pyspectre.scanner --dir ./src/module2 --log part2.json
```

#### False Positives
- PySpectre may report issues that cannot happen in practice
- Review counterexamples to verify if the issue is real
- Consider the symbolic analysis limitations (no runtime type info)

### Getting Help

```bash
# Show help
python -m pyspectre.scanner --help

# Version info
python -c "import pyspectre; print(pyspectre.__version__)"
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (may have found issues) |
| 1 | Error (invalid arguments, file not found, etc.) |

---

## See Also

- [Scanner API Documentation](SCANNER.md) - Python API for scanner
- [API Reference](API.md) - Full Python API reference
- [Examples](../examples/) - Code examples
