# PySyMex

> [!IMPORTANT]
> **EDUCATIONAL PURPOSES ONLY**
> This project is a research prototype designed for studying symbolic execution and formal verification concepts.
> It is **NOT** intended for production use, security auditing, or critical systems verification.
> Use at your own risk.

<div align="center">

**Python Symbolic Execution Engine powered by Z3 Theorem Prover**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Alpha](https://img.shields.io/badge/Status-v0.1.0--alpha-orange.svg)]()

*Mathematically prove your Python code won't crash.*

</div>

---

## Overview

**PySyMex** (Python Symbolic Execution) is a bytecode-level symbolic execution engine that uses the Z3 SMT solver to formally verify Python programs. It explores all possible execution paths through your code, building mathematical constraints at each decision point, then uses Z3 to find concrete inputs that trigger bugs — or prove no such inputs exist.

### What it does

- Disassembles Python bytecode (CPython 3.11–3.13)
- Symbolically executes every reachable path
- Builds Z3 constraints at branches, arithmetic, and API calls
- Reports bugs with **counterexamples** (concrete crashing inputs)
- Tracks taint from untrusted sources to dangerous sinks

## Features

- **Full Symbolic Execution Engine** — bytecode-level analysis with CPython 3.13 opcode support
- **Interprocedural Analysis** — tracks bugs across function calls via call graph and function summaries
- **12+ Bug Detectors** — division by zero, null dereference, index/key errors, type errors, assertion failures, dead code, taint violations, integer overflow, and more
- **Taint Tracking** — follows untrusted data through your code to detect injection vulnerabilities
- **Abstract Interpretation** — interval, sign, and parity domains with widening for loop analysis
- **Z3 SMT Integration** — formal proofs via incremental solver with caching and portfolio solving
- **Loop Handling** — bound inference, induction variable detection, loop summarization, and widening
- **Multiple Output Formats** — text, JSON, HTML, SARIF 2.1.0 (GitHub Security tab compatible)
- **Watch Mode** — incremental re-analysis on file changes during development
- **Parallel Scanning** — multi-process file verification for large codebases

## Installation

```bash
# Install Z3 solver (required)
pip install z3-solver

# Clone and install
git clone https://github.com/darkoss1/pysymex.git
cd pysymex
pip install -e .
```

## Quick Start

### Command Line

```bash
# Scan a file
pysymex scan mycode.py

# Scan a directory recursively
pysymex scan src/ -r

# Generate SARIF report for CI/CD
pysymex scan src/ --format sarif -o report.sarif

# Analyze a specific function with type hints
pysymex analyze mycode.py -f risky_func --args x:int y:str

# Watch mode — re-scan on file changes
pysymex scan . --watch

# Run benchmarks
pysymex benchmark --format markdown
```

### Python API

```python
from pysymex.analysis.solver import verify_function

def risky_divide(x: int, y: int) -> int:
    return x // y

results = verify_function(risky_divide)
for r in results:
    if r.can_crash:
        print(f"Bug: {r.crash.description}")
        print(f"Counterexample: {r.counterexample}")
```

```python
from pysymex.analysis.solver import Z3Engine

engine = Z3Engine(
    timeout_ms=5000,
    interprocedural=True,
    track_taint=True,
)
file_results = engine.verify_file("mycode.py")
```

## Bug Types Detected

| Bug Type | Description | Example |
|----------|-------------|---------|
| Division by Zero | Division where denominator can be 0 | `x / y` where `y=0` |
| Modulo by Zero | Modulo where divisor can be 0 | `x % y` where `y=0` |
| Negative Shift | Bit shift with negative amount | `x << n` where `n<0` |
| Index Out of Bounds | Array access beyond bounds | `arr[i]` where `i >= len(arr)` |
| None Dereference | Accessing attributes on None | `obj.method()` where `obj=None` |
| Type Error | Type mismatch in operations | Operations on wrong types |
| Key Error | Dictionary key not found | `d[key]` where key missing |
| Attribute Error | Missing attribute access | Missing method/property |
| Assertion Failure | Assertions that can fail | `assert x > 0` where `x<=0` |
| Unreachable Code | Dead code paths | Code after `return` |
| Taint Violation | Untrusted data to dangerous sink | SQL injection, command injection |
| Integer Overflow | Arithmetic overflow | Large number operations |

## Example Output

```
══════════════════════════════════════════════════════════════════════
 🔍 PySyMex — Formal Verification Report
    Symbolic Execution with Z3 Theorem Prover
══════════════════════════════════════════════════════════════════════

🔴 CRASHES PROVEN POSSIBLE (Z3 found counterexamples):
──────────────────────────────────────────────────────────────────────

  ➗ [DIVISION BY ZERO]
    🔴 mycode.py:12 in unsafe_divide()
       Division by zero: y can be 0 in //
       💡 Crash when: y=0

══════════════════════════════════════════════════════════════════════
 📊 Summary
══════════════════════════════════════════════════════════════════════
  📁 Files scanned:       5
  🔧 Functions analyzed:  23
  🔴 Potential crashes:   3
  ✅ Proven safe:         45
  🔗 Call relationships:  12
  ⏱️  Total time:          1.23s
```

## Architecture

```
pysymex/
├── analysis/              # Analysis engines
│   ├── solver/            # Core Z3 verification
│   ├── abstract/          # Abstract interpretation domains
│   ├── detectors/         # Bug detectors
│   ├── taint/             # Taint tracking
│   └── ...                # 35+ analysis modules
├── core/                  # Core symbolic types
│   ├── types.py           # SymbolicValue, SymbolicString, SymbolicList, etc.
│   ├── state.py           # VM state management (stack, locals, constraints)
│   ├── solver.py          # Z3 solver wrapper (incremental, portfolio)
│   └── ...
├── execution/             # Bytecode execution
│   ├── executor.py        # Main symbolic executor
│   ├── opcodes/           # Per-opcode handlers (CPython 3.11–3.13)
│   └── verified_executor.py
├── models/                # Built-in stdlib models (100+ functions)
├── reporting/             # HTML, SARIF, JSON, text output
├── contracts/             # Design-by-contract (experimental)
└── plugins/               # Plugin system for custom detectors
```

## Running Tests

```bash
# Run all tests (~2500 tests)
pytest tests/ -v

# Run specific modules
pytest tests/test_z3_prover.py -v
pytest tests/test_interprocedural.py -v

# Run with coverage
pytest --cov=pysymex tests/ -v
```

## CLI Reference

```
usage: pysymex scan [-h] [-r] [--format {text,json,sarif}] [-o OUTPUT]
                    [--max-paths MAX_PATHS] [--timeout TIMEOUT] [-v]
                    [--workers WORKERS] [--auto] [--watch]
                    path

positional arguments:
  path                  Python file or directory to scan

options:
  -r, --recursive       Recursively scan directories
  --format {text,json,sarif}  Output format (default: text)
  -o OUTPUT             Output file path (default: stdout)
  --max-paths N         Max paths per function (default: 1000)
  --timeout SECONDS     Timeout per function (default: 60)
  -v, --verbose         Verbose output
  --workers N           Number of worker processes (default: CPU count)
  --auto                Auto-tune configuration based on complexity
  --watch               Watch for file changes and re-scan

```

## Requirements

- Python 3.11+ (tested on 3.11, 3.12, 3.13)
- z3-solver >= 4.12.0

## License

MIT License — see [LICENSE](LICENSE).

## Contributing

Contributions welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Run tests (`pytest tests/ -v`)
4. Commit and push
5. Open a Pull Request
