# Changelog

All notable changes to PySyMex will be documented in this file.

## [0.1.0-alpha] - 2026-03-01

### Initial Release

First public alpha release of PySyMex (Python Symbolic Execution Engine).

#### Core Engine
- **Symbolic Execution Engine**: Full CPython 3.11–3.13 bytecode-level analysis
  - 100+ opcode handlers including Python 3.13 paired instructions (`STORE_FAST_STORE_FAST`, `LOAD_FAST_LOAD_FAST`, etc.)
  - Precision-guided exception handling with `SETUP_FINALLY` block tracking
  - Path exploration strategies: DFS, BFS, coverage-guided
- **Z3 SMT Solver Integration**: Incremental solver with push/pop scope management, caching, and portfolio solving
- **Symbolic Types**: `SymbolicValue`, `SymbolicString`, `SymbolicList`, `SymbolicDict`, `SymbolicNone` with full Z3 constraint modeling
- **VM State Management**: Copy-on-write state forking, structural constraint hashing, atomic path IDs

#### Analysis
- **12+ Bug Detectors**: Division by zero, modulo by zero, negative shift, index errors, key errors, None dereference, type errors, attribute errors, assertion failures, unreachable code, taint violations, integer overflow
- **Interprocedural Analysis**: Call graph construction, function summaries, cross-function return type inference
- **Taint Tracking**: Source-to-sink taint propagation with implicit flow tracking
- **Abstract Interpretation**: Interval, Sign, Parity, and Null lattice domains with product domain, widening, narrowing, and loop fixpoint computation
- **False Positive Reduction**: Dataclass awareness, context-sensitive exception analysis, known-crashy API allowlists, finding deduplication, and confidence scoring

#### Infrastructure
- **CLI**: `pysymex scan`, `pysymex analyze`, `pysymex verify`, `pysymex concolic`, `pysymex benchmark`
- **Output Formats**: Text, JSON, HTML, SARIF 2.1.0
- **Watch Mode**: Incremental re-analysis on file changes
- **Parallel Scanning**: Multi-process file verification
- **100+ stdlib models**: `pathlib`, `operator`, `copy`, `io`, `heapq`, `bisect`, `enum`, `dataclasses`, `collections`, `itertools`, `functools`, and more
- **Plugin System**: Custom detector registration
- **2583 tests**: Comprehensive test suite with stress tests for core components

#### Known Limitations
- State deduplication uses constraint count heuristic (can merge states with different constraints but same count)
- `lru_cache` with Z3 expressions as keys (theoretical hash collision risk, extremely unlikely in practice)
- Heap modeling is approximate — complex object attribute tracking may produce false positives
- UNKNOWN solver results treated as UNSAT (conservative, may miss some bugs)
