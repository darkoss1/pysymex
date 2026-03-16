# PySyMex Roadmap

## Released

### v0.1.0-alpha.1 ✅
**Released:** March 2026

- [x] CHTD: Constraint Hypergraph Treewidth Decomposition (O(N*2^w) path exploration)
- [x] Constraint independence optimization (KLEE-style query slicing)
- [x] Adaptive path selection via Thompson Sampling (Beta-Bernoulli bandit)
- [x] Theory-aware solver dispatch (QF_LIA, QF_S, QF_BV auto-detection)
- [x] Exception forking for try/except dual-path exploration (Python 3.12+)
- [x] Branch affinity fast path (single-sort Z3 expressions)
- [x] 13 pre-existing bug fixes across core engine
- [x] 2723 tests passing, 0 failures
- [x] Stress-tested with 12 path-explosion scenarios (up to 2^13 theoretical paths)

### v0.1.0-alpha ✅
**Released:** March 2026

- [x] Full symbolic execution engine (CPython 3.11-3.13 bytecodes)
- [x] Z3 SMT solver integration with incremental/portfolio solving
- [x] 12+ bug detectors with counterexample generation
- [x] Interprocedural analysis with call graph and function summaries
- [x] Taint tracking (source -> sink)
- [x] Abstract interpretation (Interval, Sign, Parity domains)
- [x] False positive reduction pipeline
- [x] CLI with scan, analyze, verify, benchmark commands
- [x] Output: text, JSON, HTML, SARIF 2.1.0
- [x] Watch mode and parallel scanning
- [x] 100+ stdlib models
- [x] 2583 tests passing

---

## Upcoming

### v0.1.1 — Detection Depth
**Theme:** Deeper analysis, more bug categories

- [ ] Inter-module taint tracking
- [ ] Escape analysis for resource leaks
- [ ] Path traversal detection
- [ ] Unsafe deserialization detection
- [ ] Format string injection
- [ ] Sanitizer-aware taint tracking
- [ ] Custom taint sources/sinks via config

### v0.1.2 — Contract System
**Theme:** Formal specifications

- [ ] `@requires` / `@ensures` / `@invariant` decorators
- [ ] Contract violation detection via symbolic execution
- [ ] Contract inference from existing code
- [ ] Integration with `typing` annotations as lightweight contracts

### v0.1.3 — CI/CD Integration
**Theme:** Developer workflow

- [ ] GitHub Actions workflow template
- [ ] Pre-commit hook
- [ ] Baseline file support (`.pysymex-baseline`)
- [ ] Diff-only mode (scan changed lines in PRs)
- [ ] JUnit XML output

### v0.1.4 — IDE & Ecosystem
**Theme:** Real-time experience

- [ ] LSP server for real-time analysis
- [ ] VS Code extension
- [ ] Plugin system for custom detectors
- [ ] Per-project config (`.pysymex.toml`)
- [ ] Inline suppression comments (`# pysymex: ignore[RULE]`)

### v1.0.0 — Stable Release
**Theme:** Production-ready

- [ ] <10% false positive rate on top 100 PyPI packages
- [ ] Full documentation site
- [ ] PyPI publication
- [ ] Tested on Django, Flask, FastAPI, NumPy

---

## Priority Matrix

| Priority | Focus Area |
|----------|------------|
| P0 | Crash fixes, correctness issues |
| P1 | False positive reduction, detection accuracy |
| P2 | New detectors, analysis improvements |
| P3 | IDE/CI integration, quality of life |

---

*Last updated: March 15, 2026*
