# pysymex

> **Python Symbolic Execution Engine powered by Z3 Theorem Prover**
> Mathematically prove your Python code won't crash.

```python
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   p y s y m e x                                                              ║
║   ─────────────────────────────────────────────────────────────────────────  ║
║   Symbolic Execution · Formal Verification · Z3-Powered                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-yellow.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Status: Alpha-4.0](https://img.shields.io/badge/Status-Alpha-orange.svg)]()
[![Z3 Solver](https://img.shields.io/badge/Solver-Z3-blueviolet.svg)](https://github.com/Z3Prover/z3)

---

> **EDUCATIONAL PURPOSES ONLY**
>
> This project is a research prototype designed for studying symbolic execution and formal verification concepts.
> It is **NOT** intended for production use, security auditing, or critical systems verification. Use at your own risk.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [Bug Types Detected](#4-bug-types-detected)
5. [Architecture](#5-architecture)
6. [Development](#6-development)
7. [Requirements](#7-requirements)
8. [Contributing](#8-contributing)
9. [License](#9-license)
10. [Documentation](#10-documentation)

---

## 1. Overview

**pysymex** (Python Symbolic Execution) is a bytecode-level symbolic execution engine that uses the Z3 SMT solver to formally verify Python programs. It explores all possible execution paths through your code, building mathematical constraints at each decision point, then uses Z3 to find concrete inputs that trigger bugs — or prove no such inputs exist.

### What It Does

- **Disassembles Python bytecode** (CPython 3.11–3.13)
- **Symbolically executes** every reachable path
- **Reports bugs** with counterexamples (concrete crashing inputs)
- **Interprocedural Analysis** — crosses function boundaries via call graphs and summaries
- **Asynchronous Execution** — high-throughput scanning with asyncio and process pools

### Features

| Category | Features |
|----------|----------|
| **Engine** | Bytecode-level symbolic execution, CPython 3.13 opcode support, Z3 SMT integration |
| **Optimization** | CHTD path explosion mitigation, constraint independence (KLEE-style), adaptive path selection |
| **Analysis** | Interprocedural analysis, abstract interpretation (interval/sign/parity), loop handling |
| **Output** | Text, JSON, HTML, SARIF 2.1.0 (GitHub Security tab compatible), Rich (colored panels) |
| **Safety** | 20+ bug types, 40+ detectors, sandbox isolation |

---

## 2. Installation

### From PyPI

```bash
pip install pysymex
```

### From Source (Development)

```bash
git clone https://github.com/darkoss1/pysymex.git
cd pysymex
pip install -e ".[dev]"
```

---

## 3. Quick Start

### Command Line

```bash
# Scan a file
pysymex scan mycode.py

# Scan a directory recursively
pysymex scan src/ -r

# Generate SARIF report for CI/CD
pysymex scan src/ --format sarif -o report.sarif

# Analyze a specific function
pysymex analyze mycode.py -f risky_func --args x:int y:str

# Watch mode — re-scan on file changes
pysymex scan . --watch
```

### Python API

```python
from pysymex import analyze

def risky_divide(x: int, y: int) -> int:
    return x // y

# Analyze for potential crashes
result = analyze(risky_divide, {"x": "int", "y": "int"})

for issue in result.issues:
    print(f"Bug: {issue.message}")
    print(f"Counterexample: {issue.counterexample}")
```

### Example Output

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│ pysymex - Formal Verification Report                                         │
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

---

## 4. Bug Types Detected

| Bug Type | Description | Example |
|----------|-------------|---------|
| Division by Zero | Division where denominator can be 0 | `x / y` where `y=0` |
| Modulo by Zero | Modulo where divisor can be 0 | `x % y` where `y=0` |
| Index Error | Array access beyond bounds | `arr[i]` where `i >= len(arr)` |
| Key Error | Dictionary key not found | `d[key]` where key missing |
| Attribute Error | Missing attribute access | `obj.missing_attr` |
| None Dereference | Accessing attributes on None | `obj.method()` where `obj=None` |
| Type Error | Type mismatch in operations | `str + int` |
| Value Error | Invalid value for operation | `int("abc")` |
| Assertion Error | Assertions that can fail | `assert x > 0` |
| Overflow Error | Arithmetic overflow | `x + 1` where `x = MAX_INT` |
| Unbound Local | Using unbound local variable | `print(x)` before assignment |
| Name Error | Using undefined name | `print(undefined_var)` |
| Resource Leak | Unclosed files or connections | `f = open(p); return` |
| Dead Code | Code that never executes | Code after absolute `return` |
| Unreachable Code | Code that cannot be reached | Code after `raise Exception` |
| Infinite Loop | Loop that never terminates | `while True: pass` |
| Injection | Code injection vulnerabilities | SQL injection, command injection |
| Syntax Error | Invalid syntax patterns | Malformed code constructs |
| Logical Contradiction | Impossible logical conditions | `if x > 10 and x < 5` |
| Contract Violation | Violated function contracts | Pre/post condition failures |

---

## 5. Architecture

```python
pysymex/
├── analysis/              # Analysis engines
│   ├── solver/            # Z3 verification core
│   ├── abstract/          # Abstract interpretation
│   ├── detectors/         # Bug detectors (40+)
│   └── path_manager.py    # Path selection
├── core/                  # Engine foundation
│   ├── types/             # Symbolic primitives
│   ├── state.py           # VM state management
│   └── solver.py          # Z3 wrapper
├── execution/             # Bytecode VM
│   ├── dispatcher.py      # Opcode dispatch
│   └── opcodes/           # Handlers (3.11-3.13)
├── accel/                 # Hardware acceleration
│   └── backends/          # CPU backends
├── models/                # Stdlib models (700+)
├── reporting/             # Output formatters
└── scanner/               # Static scanner
```

---

## 6. Development

### Setup

```bash
# Format code
ruff format pysymex tests

# Type checking
pyright pysymex

# Run tests
pytest tests/ -v

# Run with coverage
pytest --cov=pysymex tests/ -v
```

---

## 7. Requirements

- **Python 3.11+** (tested on 3.11, 3.12, 3.13)
- `z3-solver` == 4.15.3.0
- `pydantic` == 2.12.5
- `immutables` == 0.20
- `numpy` == 2.0.0
- `numba` == 0.64.0

**Note**: Dependency versions are pinned to specific known-working versions. Update after verifying compatibility.

---

## 8. Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Formatting and type-check commands
- Testing expectations
- Pull request guidelines

---

## 9. License

**AGPL-3.0 License** — see [LICENSE](LICENSE).

---

## 10. Documentation

> [!NOTE]
> **Temporary Automated Documentation**
> An automatically generated Code Wiki providing an architectural deep-dive and component reference is available at: [https://codewiki.google/github.com/darkoss1/pysymex](https://codewiki.google/github.com/darkoss1/pysymex)
>
> **Important Notices:**
> - The Wiki is generated automatically but may take time to refresh; please verify the generation and commit dates on the page.
> - It may be **slightly outdated** compared to the latest `main` branch.
> - This is **NOT** official documentation and is provided for research and architectural exploration purposes only. Do not fully rely on it for production implementation details.

---

<div align="center">
  <sub>Built for Formal Verification</sub>
</div>
