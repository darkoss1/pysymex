# pysymex Scanner - Complete Guide

Detailed documentation for the pysymex Scanner module and standalone auto-scanner.

---

## Table of Contents

1. [Overview](#overview)
2. [Python API](#python-api)
3. [Auto-Scanner Usage](#auto-scanner-usage)
4. [Watch Mode](#watch-mode)
5. [Session Logging](#session-logging)
6. [Integration Examples](#integration-examples)
7. [API Reference](#api-reference)

---

## Overview

pysymex provides two ways to scan Python files:

| Method | File | Use Case |
|--------|------|----------|
| **Module Scanner** | `pysymex/scanner.py` | Integrated with pysymex package |
| **Standalone Scanner** | `auto_scanner.py` | Copy to any project, no installation |

Both provide identical functionality:
- Single file and directory scanning
- Watch mode for continuous monitoring
- JSON session logging
- Detailed issue reporting with counterexamples

---

## Python API

### Quick Start

```python
from pysymex import scan_file, scan_directory

# Scan a single file
result = scan_file("mycode.py")
print(f"Found {len(result.issues)} issues")

# Scan a directory
results = scan_directory("./src")
total = sum(len(r.issues) for r in results)
print(f"Total issues: {total}")
```

### scan_file()

Scan a single Python file for potential bugs.

```python
from pysymex import scan_file

result = scan_file(
    file_path="path/to/file.py",  # Required: file to scan
    verbose=False,                 # Print output to console
    max_paths=100,                 # Max paths per function
    timeout=30.0                   # Timeout in seconds
)

# Access results
print(f"File: {result.file_path}")
print(f"Issues: {len(result.issues)}")
print(f"Code objects: {result.code_objects}")
print(f"Paths explored: {result.paths_explored}")
print(f"Error: {result.error}")  # None if successful

# Iterate issues
for issue in result.issues:
    print(f"[{issue['kind']}] {issue['message']} (Line {issue['line']})")
    if issue['counterexample']:
        for var, val in issue['counterexample'].items():
            print(f"    {var} = {val}")
```

### scan_directory()

Scan all Python files in a directory.

```python
from pysymex import scan_directory

results = scan_directory(
    dir_path="./src",           # Required: directory to scan
    pattern="**/*.py",          # Glob pattern (default: recursive)
    verbose=True,               # Show progress
    max_paths=100,              # Max paths per function
    timeout=30.0                # Timeout per file
)

# Process results
for result in results:
    if result.issues:
        print(f"\n{result.file_path}:")
        for issue in result.issues:
            print(f"  Line {issue['line']}: {issue['message']}")

# Summary statistics
total_files = len(results)
files_with_issues = sum(1 for r in results if r.issues)
total_issues = sum(len(r.issues) for r in results)
files_clean = sum(1 for r in results if not r.issues and not r.error)
files_error = sum(1 for r in results if r.error)

print(f"""
Summary:
  Files scanned: {total_files}
  With issues:   {files_with_issues}
  Clean:         {files_clean}
  Errors:        {files_error}
  Total issues:  {total_issues}
""")
```

### ScanResult Object

```python
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class ScanResult:
    file_path: str                      # Absolute path to file
    timestamp: str                      # ISO format timestamp
    issues: List[Dict[str, Any]]        # List of issues found
    code_objects: int                   # Number of functions/classes
    paths_explored: int                 # Symbolic paths analyzed
    error: str                          # Error message or None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        ...
```

### Issue Dictionary Format

Each issue in `ScanResult.issues` is a dictionary:

```python
{
    "kind": "DIVISION_BY_ZERO",    # Issue type (string)
    "message": "Division by zero possible",  # Human-readable message
    "line": 15,                     # Line number (1-based)
    "pc": 24,                       # Bytecode offset
    "counterexample": {             # Values that trigger the bug
        "y": "0",
        "x": "42"
    }
}
```

---

## Auto-Scanner Usage

The `auto_scanner.py` file is a standalone scanner you can copy to any project.

### Setup

1. Copy `auto_scanner.py` to your project root
2. Ensure pysymex is installed: `pip install pysymex`
3. Run the scanner

### Command Line

```bash
# Basic scan (current directory)
python auto_scanner.py

# Scan specific directory
python auto_scanner.py --dir ./src

# Custom log file
python auto_scanner.py --dir ./src --log results.json

# Watch mode
python auto_scanner.py --dir ./src --watch
```

### Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--dir` | `-d` | `.` | Directory to scan |
| `--log` | `-l` | auto-generated | Log file path |
| `--watch` | `-w` | False | Enable continuous monitoring |
| `--recursive` | `-r` | True | Scan subdirectories |

---

## Watch Mode

Watch mode continuously monitors for file changes and re-scans modified files.

### Starting Watch Mode

```bash
# CLI
python -m pysymex.scanner --dir ./src --watch

# Or with standalone scanner
python auto_scanner.py --dir ./src --watch
```

### Watch Mode Output

```
╔══════════════════════════════════════════════════════════════════════╗
║                   pysymex Scanner - Watch Mode                     ║
╠══════════════════════════════════════════════════════════════════════╣
║  Watching: ./src                                                     ║
║  Log:      scan_log_20260117_120000.json                            ║
║  Press Ctrl+C to stop and see summary.                               ║
╚══════════════════════════════════════════════════════════════════════╝

👁️  Watching for file changes...

======================================================================
🔍 Scanning: ./src/utils.py
======================================================================

⚠️  Found 1 potential issues:

   • [DIVISION_BY_ZERO] Division by zero possible (Line 15)
       └─ y = 0

   📊 Stats: 5 code objects | 42 paths explored
```

### Stopping Watch Mode

Press `Ctrl+C` to stop. The session summary will be displayed:

```
Stopping watcher...

======================================================================
📋 SESSION SUMMARY
======================================================================

   Files scanned:     15
   Files with issues: 3
   Files clean:       11
   Files with errors: 1
   
   Total issues:      7

   Issue breakdown:
      DIVISION_BY_ZERO            3 ███
      INDEX_ERROR                 2 ██
      NULL_DEREFERENCE            2 ██

   📁 Log saved to: scan_log_20260117_120000.json
======================================================================

Done.
```

---

## Session Logging

Every scan session automatically saves results to a JSON log file.

### Log File Location

Default: `scan_log_YYYYMMDD_HHMMSS.json` in current directory

Custom: Use `--log` argument or set in code

### Log File Structure

```json
{
  "session_start": "2026-01-17T12:00:00.000000",
  "last_update": "2026-01-17T12:05:30.000000",
  "total_files": 15,
  "total_issues": 7,
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
    },
    {
      "file": "./src/parser.py",
      "timestamp": "2026-01-17T12:00:10.000000",
      "issues": [],
      "code_objects": 12,
      "paths_explored": 156,
      "error": null
    }
  ]
}
```

### Using ScanSession in Code

```python
from pysymex.scanner import ScanSession, analyze_file
from pathlib import Path

# Create session with custom log file
session = ScanSession(log_file=Path("my_scan.json"))

# Scan files and track in session
for file_path in Path("./src").glob("**/*.py"):
    result = analyze_file(file_path)
    session.add_result(result)  # Auto-saves to log file

# Get summary
summary = session.get_summary()
print(f"Files: {summary['files_scanned']}")
print(f"Issues: {summary['total_issues']}")
print(f"Breakdown: {summary['issue_breakdown']}")
```

---

## Integration Examples

### Example 1: Custom Report Generator

```python
from pysymex import scan_directory
from pathlib import Path
import json

def generate_report(project_dir: str, output_file: str):
    """Generate a detailed security report."""
    results = scan_directory(project_dir, verbose=False)
    
    report = {
        "project": project_dir,
        "summary": {
            "total_files": len(results),
            "files_with_issues": sum(1 for r in results if r.issues),
            "total_issues": sum(len(r.issues) for r in results),
        },
        "by_severity": {
            "high": [],    # Division by zero, null deref
            "medium": [],  # Index errors, type errors
            "low": [],     # Others
        },
        "files": []
    }
    
    HIGH_SEVERITY = {"DIVISION_BY_ZERO", "NULL_DEREFERENCE"}
    MEDIUM_SEVERITY = {"INDEX_ERROR", "TYPE_ERROR", "KEY_ERROR"}
    
    for result in results:
        if result.issues:
            file_entry = {
                "path": result.file_path,
                "issues": result.issues
            }
            report["files"].append(file_entry)
            
            for issue in result.issues:
                kind = issue["kind"]
                if kind in HIGH_SEVERITY:
                    report["by_severity"]["high"].append(issue)
                elif kind in MEDIUM_SEVERITY:
                    report["by_severity"]["medium"].append(issue)
                else:
                    report["by_severity"]["low"].append(issue)
    
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    return report

# Usage
report = generate_report("./myproject", "security_report.json")
print(f"High severity: {len(report['by_severity']['high'])}")
```

### Example 2: Pre-Commit Hook (Python)

```python
#!/usr/bin/env python3
"""Pre-commit hook for pysymex scanning."""
import subprocess
import sys
from pysymex import scan_file

def get_staged_files():
    """Get list of staged Python files."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True
    )
    return [f for f in result.stdout.strip().split("\n") if f.endswith(".py")]

def main():
    files = get_staged_files()
    if not files:
        return 0
    
    print(f"pysymex: Scanning {len(files)} staged files...")
    
    total_issues = 0
    for filepath in files:
        result = scan_file(filepath)
        if result.issues:
            print(f"\n⚠️  {filepath}: {len(result.issues)} issues")
            for issue in result.issues:
                print(f"    Line {issue['line']}: [{issue['kind']}] {issue['message']}")
            total_issues += len(result.issues)
    
    if total_issues > 0:
        print(f"\n❌ Found {total_issues} potential issues. Please review.")
        return 1
    
    print("✅ No issues found.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

### Example 3: Pytest Integration

```python
# conftest.py
import pytest
from pysymex import scan_file
from pathlib import Path

@pytest.fixture(scope="session")
def pysymex_results():
    """Run pysymex analysis on the entire project."""
    results = {}
    for py_file in Path("src").glob("**/*.py"):
        results[str(py_file)] = scan_file(py_file)
    return results

def pytest_collection_modifyitems(session, config, items):
    """Add pysymex marker to tests."""
    pass

# test_security.py
def test_no_division_by_zero(pysymex_results):
    """Ensure no division by zero issues."""
    for filepath, result in pysymex_results.items():
        div_issues = [i for i in result.issues if i["kind"] == "DIVISION_BY_ZERO"]
        assert not div_issues, f"{filepath} has division by zero issues: {div_issues}"

def test_no_high_severity_issues(pysymex_results):
    """Ensure no high severity issues."""
    HIGH_SEVERITY = {"DIVISION_BY_ZERO", "NULL_DEREFERENCE"}
    for filepath, result in pysymex_results.items():
        high = [i for i in result.issues if i["kind"] in HIGH_SEVERITY]
        assert not high, f"{filepath} has high severity issues: {high}"
```

### Example 4: Flask/Django Middleware

```python
# middleware.py
from pysymex import scan_file
import logging

logger = logging.getLogger("pysymex.middleware")

def analyze_on_import(filepath):
    """Analyze a module when it's imported (development only)."""
    try:
        result = scan_file(filepath, verbose=False, timeout=5.0)
        if result.issues:
            logger.warning(
                f"pysymex found {len(result.issues)} issues in {filepath}"
            )
            for issue in result.issues:
                logger.warning(
                    f"  [{issue['kind']}] Line {issue['line']}: {issue['message']}"
                )
    except Exception as e:
        logger.debug(f"pysymex analysis failed for {filepath}: {e}")
```

---

## API Reference

### Functions

#### `scan_file(file_path, verbose=False, max_paths=100, timeout=30.0) -> ScanResult`

Scan a single Python file.

**Parameters:**
- `file_path` (str | Path): Path to the Python file
- `verbose` (bool): Print detailed output (default: False)
- `max_paths` (int): Maximum paths to explore per function (default: 100)
- `timeout` (float): Timeout in seconds (default: 30.0)

**Returns:** ScanResult object

---

#### `scan_directory(dir_path, pattern="**/*.py", verbose=True, max_paths=100, timeout=30.0) -> List[ScanResult]`

Scan all Python files in a directory.

**Parameters:**
- `dir_path` (str | Path): Path to the directory
- `pattern` (str): Glob pattern for files (default: "**/*.py" for recursive)
- `verbose` (bool): Print progress (default: True)
- `max_paths` (int): Maximum paths per function (default: 100)
- `timeout` (float): Timeout per file (default: 30.0)

**Returns:** List of ScanResult objects

---

### Classes

#### `ScanResult`

Result of scanning a single file.

**Attributes:**
- `file_path` (str): Absolute path to the scanned file
- `timestamp` (str): ISO format timestamp of the scan
- `issues` (List[Dict]): List of issues found
- `code_objects` (int): Number of code objects analyzed
- `paths_explored` (int): Number of symbolic paths explored
- `error` (str | None): Error message if scan failed

**Methods:**
- `to_dict() -> Dict`: Convert to dictionary for JSON serialization

---

#### `ScanSession`

Tracks all scans in a session with automatic logging.

**Constructor:**
- `ScanSession(log_file: Path = None)`

**Attributes:**
- `results` (List[ScanResult]): All scan results
- `start_time` (datetime): Session start time
- `log_file` (Path): Path to log file

**Methods:**
- `add_result(result: ScanResult)`: Add a scan result (auto-saves to log)
- `get_summary() -> Dict`: Get session statistics

---

## Issue Types

| Kind | Description | Severity |
|------|-------------|----------|
| `DIVISION_BY_ZERO` | Division where denominator can be zero | High |
| `NULL_DEREFERENCE` | Accessing attribute/method of None | High |
| `INDEX_ERROR` | Array/list index out of bounds | Medium |
| `KEY_ERROR` | Dictionary key not found | Medium |
| `TYPE_ERROR` | Type mismatch in operation | Medium |
| `ASSERTION_ERROR` | Assertion can fail | Medium |
| `FORMAT_STRING_ERROR` | String formatting issues | Low |
| `RESOURCE_LEAK` | Unclosed file/resource | Low |

---

## Best Practices

1. **Start with default settings** - They work well for most codebases
2. **Review counterexamples** - They show the inputs that cause issues
3. **Use watch mode during development** - Catch issues early
4. **Integrate with CI/CD** - Prevent issues from reaching production
5. **Handle timeouts gracefully** - Large functions may need more time
6. **Check log files** - Full details are saved in JSON format

---

## See Also

- [CLI Guide](CLI.md) - Command-line interface documentation
- [API Reference](API.md) - Full Python API reference
