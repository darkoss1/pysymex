# PySpectre Roadmap

## Current Status: v0.3.0-alpha ✅

**Released:** February 2026
**Focus:** Accuracy, false positive reduction, precision

---

## v0.3.0 - False Positive Reduction ✅
**Released:** February 2026
**Theme:** Accuracy & Precision

### Goals
- [x] Reduce false positive rate from ~50% to <25%
- [x] Add type annotation awareness (filter `Callable`, `ParamSpec` noise)
- [ ] Distinguish intentional vs accidental assertions (In Progress)
- [x] Add confidence scores to detections

### Features
- [x] Type annotation filter for common FP patterns
- [x] Assertion context analyzer (security guard vs bug)
- [x] Detection confidence scoring (high/medium/low)
- [x] Severity classification improvements
- [x] SARIF 2.1.0 output support
- [x] New analysis modules (Resource, String, Exception)

### Stdlib Models
- [x] `collections` module (Counter, defaultdict, deque)
- [x] `itertools` module (chain, islice, groupby)
- [x] `functools` module (partial, reduce, lru_cache)
- [ ] `typing` module (better generic support)

---

## v0.4.0 - Performance & Scale
**Target:** March 2026
**Theme:** Speed & Efficiency

### Goals
- [ ] 2x faster scan times on large codebases
- [ ] Handle 10,000+ line files without timeout
- [ ] Memory usage optimization

### Features
- [ ] Incremental analysis (only re-scan changed files)
- [ ] Parallel file processing
- [ ] Smart caching of analysis results
- [ ] Configurable timeout per function/file

### Benchmarks
- [ ] Establish baseline metrics
- [ ] Performance regression tests
- [ ] Memory profiling integration

---

## v0.5.0 - CI/CD Integration
**Target:** April 2026
**Theme:** Developer Workflow

### Goals
- [ ] Zero-friction CI integration
- [ ] IDE plugin support
- [ ] Pre-commit hook compatibility

### Features
- [ ] GitHub Actions workflow template
- [ ] GitLab CI configuration
- [ ] Pre-commit hook script
- [ ] Exit codes for CI (0 = pass, 1 = issues found)
- [ ] Baseline file support (ignore known issues)

### Output Formats
- [ ] SARIF improvements for GitHub Security tab
- [ ] JUnit XML for CI dashboards
- [ ] Markdown summary for PR comments

---

## v0.6.0 - Advanced Detection
**Target:** May 2026
**Theme:** Deep Analysis

### Goals
- [ ] Detect more bug categories
- [ ] Cross-function analysis improvements
- [ ] Data flow tracking

### Features
- [ ] SQL injection detection
- [ ] Command injection detection
- [ ] Path traversal detection
- [ ] Taint analysis improvements
- [ ] Cross-module analysis

### Bug Categories
- [ ] Security vulnerabilities (injection, traversal)
- [ ] Concurrency issues (race conditions)
- [ ] Resource leaks (file handles, connections)

---

## v0.7.0 - Contract System
**Target:** June 2026
**Theme:** Formal Specifications

### Goals
- [ ] Support user-defined contracts
- [ ] Pre/post conditions
- [ ] Invariants

### Features
- [ ] `@requires` decorator for preconditions
- [ ] `@ensures` decorator for postconditions
- [ ] `@invariant` decorator for class invariants
- [ ] Contract violation detection

---

## v0.8.0 - Documentation & Education
**Target:** July 2026
**Theme:** Usability

### Goals
- [ ] Complete API documentation
- [ ] Tutorial series
- [ ] Example gallery

### Deliverables
- [ ] Sphinx documentation site
- [ ] 10+ tutorial examples
- [ ] Video walkthrough
- [ ] Comparison guide (vs CrossHair, Hypothesis)

---

## v0.9.0 - Beta Polish
**Target:** August 2026
**Theme:** Production Readiness

### Goals
- [ ] Bug-free on top 100 PyPI packages
- [ ] <10% false positive rate
- [ ] Complete test coverage

### Validation
- [ ] Test on Django, Flask, FastAPI
- [ ] Test on NumPy, Pandas (limited)
- [ ] User feedback collection
- [ ] Bug bounty program (informal)

---

## v1.0.0 - Production Release
**Target:** September 2026
**Theme:** Stable & Reliable

### Requirements
- [ ] All v0.x features complete
- [ ] <10% false positive rate
- [ ] <5% missed bugs (false negatives)
- [ ] Full documentation
- [ ] CI/CD integration tested
- [ ] 3+ months of beta testing

### Launch
- [ ] PyPI package publication
- [ ] GitHub release with binaries
- [ ] Announcement blog post
- [ ] Community feedback channels

---

## Beyond v1.0

### v1.1+ Ideas
- LSP server for real-time IDE integration
- VS Code extension
- Web-based demo playground
- Plugin system for custom detectors
- Machine learning-assisted detection
- LLM integration for fix suggestions

---

## Release Cadence

| Phase | Cadence |
|-------|---------|
| Alpha (v0.x) | Monthly releases |
| Beta (v0.9) | Bi-weekly patches |
| Stable (v1.x) | Quarterly features, monthly patches |

---

## Priority Matrix

| Priority | Focus Area |
|----------|------------|
| P0 (Critical) | Crash fixes, security issues |
| P1 (High) | False positive reduction, accuracy |
| P2 (Medium) | New features, stdlib models |
| P3 (Low) | Performance, nice-to-haves |

---

*Last updated: February 2026*
