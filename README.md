# PySyMex: Python Symbolic Execution & Formal Verification

> [!IMPORTANT]
> **EDUCATIONAL PURPOSES ONLY**
> This project is a research prototype designed for studying symbolic execution and formal verification concepts.
> It is **NOT** intended for production use, security auditing, or critical systems verification.
> Use at your own risk.

<div align="center">

**Python Symbolic Execution Engine powered by Z3 Theorem Prover**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL--3.0](https://img.shields.io/badge/License-AGPL--3.0-yellow.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Status: Alpha](https://img.shields.io/badge/Status-v0.1.0--alpha.3-orange.svg)]()

*Mathematically prove your Python code won't crash.*

</div>

---

## Overview

**PySyMex** (Python Symbolic Execution) is a bytecode-level symbolic execution engine that uses the Z3 SMT solver to formally verify Python programs. It explores all possible execution paths through your code, building mathematical constraints at each decision point, then uses Z3 to find concrete inputs that trigger bugs — or prove no such inputs exist.

### What it does

- Disassembles Python bytecode (CPython 3.11–3.13)
- Symbolically executes every reachable path
- Reports bugs with **counterexamples** (concrete crashing inputs)
- Tracks taint from untrusted sources to dangerous sinks
- **Interprocedural Analysis** — crosses function boundaries via call graphs and summaries
- **Asynchronous Execution** — high-throughput scanning with `asyncio` and process pools

## Features
- **Hardware Acceleration (`h_acceleration`)** — Evaluates Boolean constraints near theoretical hardware limits via **CuPy NVRTC** direct CUDA C++ compilation. Includes instruction-level parallelism (ILP) unrolling and warp shuffle reductions. Seamlessly falls back to optimized multi-threaded Numba CPU execution.
- **Hardened Sandbox Isolation** — strict path sanitization, resolved-path containment checks, backend capability validation, and Windows Job Object memory-limit enforcement.
- **Full Symbolic Execution Engine** — bytecode-level analysis with robust CPython 3.13 opcode support.
- **CHTD Path Explosion Mitigation** — Constraint Hypergraph Treewidth Decomposition reduces path exploration from O(2^B) to O(N*2^w) for bounded-treewidth programs.
- **Constraint Independence Optimization** — KLEE-style constraint slicing partitions queries into independent clusters, reducing solver load by 60-90%.
- **Adaptive Path Selection** — Thompson Sampling (Beta-Bernoulli bandit) balances CHTD-native, coverage-guided, and random exploration strategies.
- **Theory-Aware Solver Dispatch** — auto-detects QF_LIA/QF_S/QF_BV theories and tunes Z3 parameters per query.
- **Exception Forking** — explores both success and exception paths for try/except blocks using Python 3.12+ exception tables.
- **Interprocedural Analysis** — tracks bugs across function calls via global call graph and function summaries.
- **25+ Bug Types (40+ Detectors)** — handles everything from division by zero to path traversal and SQL injection.
- **Taint Tracking** — fine-grained data flow tracking from untrusted sources to dangerous sinks.
- **Abstract Interpretation** — interval, sign, and parity domains with widening for rapid loop convergence.
- **Z3 SMT Integration** — formal proofs via incremental solver with caching and portfolio solving.
- **Loop Handling** — bound inference, induction variable detection, loop summarization, and widening.
- **Multiple Output Formats** — text, JSON, HTML, SARIF 2.1.0 (GitHub Security tab compatible).
- **Watch Mode** — incremental re-analysis on file changes during development.
- **Parallel Scanning** — process-level parallelism for multi-core verification scaling for large codebases

## Installation

Install directly from PyPI:

```bash
# Standard installation (Basic pure-Python engine)
pip install pysymex

# High-Performance CPU Mode (Installs Numba & NumPy)
pip install "pysymex[accel-cpu]"

# Extreme-Performance GPU Mode (Installs CuPy for NVIDIA GPUs)
pip install "pysymex[accel-gpu]"
```

Or install from source for development:

```bash
git clone https://github.com/darkoss1/pysymex.git
cd pysymex
pip install -e ".[dev]"
```

## Development

Common local checks:

```bash
# Format code
ruff format pysymex tests

# Strict type checking
pyright pysymex

# Run the test suite
pytest tests/ -v
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

## Documentation

> [!NOTE]
> **Temporary Automated Documentation**
> An automatically generated Code Wiki providing an architectural deep-dive and component reference is available at: [https://codewiki.google/github.com/darkoss1/pysymex](https://codewiki.google/github.com/darkoss1/pysymex)
> 
> **Important Notices:**
> - The Wiki is generated automatically but may take time to refresh; please verify the generation and commit dates on the page.
> - It may be **slightly outdated** compared to the latest `main` branch.
> - This is **NOT** official documentation and is provided for research and architectural exploration purposes only. Do not fully rely on it for production implementation details.

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

```python
from pysymex import Z3Engine

engine = Z3Engine(
    timeout_ms=5000,
    interprocedural=True,
    track_taint=True,
)
# Returns a mapping of function names to VerificationResults
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
| Type Error | Type mismatch in operations | `str + int` |
| Key Error | Dictionary key not found | `d[key]` where key missing |
| Attribute Error | Missing attribute access | `obj.missing_attr` |
| Assertion Failure | Assertions that can fail | `assert x > 0` |
| Unreachable Code | Dead code paths | Code after absolute `return` |
| Taint Violation | Untrusted data to dangerous sink | SQLi, Command Injection |
| Integer Overflow | Arithmetic overflow (32/64-bit) | `x + 1` where `x = MAX_INT` |
| Path Traversal | Untrusted input used in file paths | `open("/etc/" + user_input)` |
| Resource Leak | Unclosed files or connections | `f = open(p); return` |
| ValueError | Invalid arguments to builtins | `int("abc")` |

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
├── analysis/              # Advanced Analysis Engines
│   ├── solver/            # Z3 interprocedural verification core
│   ├── abstract/          # Abstract interpretation (interval, sign, parity)
│   ├── detectors/         # Bug pattern detectors (40+ implementations)
│   ├── taint/             # Taint tracking & information flow
│   ├── type_inference/    # Static type inference system
│   ├── path_manager.py    # Adaptive path selection (Thompson Sampling)
│   └── ...                # 40+ analysis modules
├── core/                  # Engine Foundation
│   ├── types.py           # Symbolic primitives (Int, Bool, String)
│   ├── types_containers.py# Symbolic List, Dict, Object models
│   ├── state.py           # VM state management (stack, locals, heap)
│   ├── solver.py          # Z3 solver wrapper (incremental, portfolio)
│   ├── treewidth.py       # Constraint Hypergraph Tree Decomposition (CHTD)
│   └── constraint_independence.py  # KLEE-style constraint slicing
├── execution/             # Bytecode Virtual Machine
│   ├── executor.py        # Main engine hub
│   ├── dispatcher.py      # Opcode dispatch with exception handling
│   ├── opcodes/           # Per-opcode handlers (3.11-3.13)
│   └── verified_executor.py
├── h_acceleration/        # Hardware-Accelerated Solvers
│   └── backends/          # GPU (CuPy NVRTC) and CPU (Numba) backends
├── models/                # Stdlib Models (700+ functions)
├── reporting/             # HTML, SARIF, JSON, Text formatters
├── scanner/               # Fast static pattern matching scanner
└── ...
```

## Running Tests

```bash
# Run all tests (5700+ items)
pytest tests/ -v

# Run specific modules
pytest tests/test_z3_prover.py -v
pytest tests/test_interprocedural.py -v

# Run with coverage
pytest --cov=pysymex tests/ -v
```

## CLI Reference

```
usage: pysymex scan [-h] [-r] [--mode {symbolic,static,pipeline}]
                    [--format {text,json,sarif}] [-o OUTPUT]
                    [--max-paths MAX_PATHS] [--timeout TIMEOUT] [-v]
                    [--workers WORKERS] [--auto] [--watch] [--no-cache]
                    path

positional arguments:
  path                  Python file or directory to scan

options:
  -r, --recursive       Recursively scan directories
  --mode {symbolic,static,pipeline}  Analysis mode (default: symbolic)
  --format {text,json,sarif}  Output format (default: text)
  -o OUTPUT             Output file path (default: stdout)
  --max-paths N         Maximum execution paths to explore (default: unlimited with CHTD)
  --timeout SECONDS     Maximum analysis time in seconds (default: 60)
  -v, --verbose         Verbose output
  --workers N           Number of worker processes (0 = auto, default: 0)
  --auto                Auto-tune configuration based on complexity
  --watch               Watch for file changes and re-scan
  --no-cache            Disable all caching for fresh analysis

```

## Requirements

- Python 3.11+ (tested on 3.11, 3.12, 3.13)
- z3-solver >= 4.12.0
- pydantic >= 2.0.0
- icontract >= 2.6.0

## License

AGPL-3.0 License — see [LICENSE](LICENSE).

## Contributing

Contributions are welcome.

Start with [CONTRIBUTING.md](CONTRIBUTING.md) for:

- development setup
- formatting and strict type-check commands
- testing expectations
- pull request guidelines
