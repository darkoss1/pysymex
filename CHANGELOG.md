# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0-alpha] - 2026-02-11

### Added
- **Intelligent False Positive Filter**: Integrated `fp_filter.py` to reduce noise from type annotations and intentional assertions.
- **Enhanced Type Inference**: `PyType` now tracks `length`, `known_keys`, and `value_constraints` for higher precision.
- **SARIF 2.1.0 Support**: Full support for static analysis results in SARIF format for CI/CD integration.
- **Static Analysis Mode**: New `static` mode for `scan` command, providing fast and reliable multi-phase analysis.
- **Confidence Scoring**: Issues now include a confidence score (high/medium/low) based on analysis depth.
- **New Analysis Modules**: Specialized analyzers for Resource Leaks, String Safety, and Exception Flow.

### Changed
- Default `scan` mode changed from `symbolic` to `static` for improved performance.
- Refactored CLI for better maintainability and reduced complexity.

### Fixed
- Line number extraction bug (boolean `starts_line` issue in Python 3.11+).
- Numerous linting warnings and technical debt items across the core engine.

## [0.2.0-alpha] - 2026-01-30

### Added
- **61 new stdlib models**:
  - `pathlib`: Path(), exists, is_file, is_dir, name, stem, suffix, parent, joinpath, /, read_text, write_text, read_bytes, write_bytes, resolve, mkdir, unlink, glob, rglob (21 models)
  - `operator`: itemgetter, attrgetter, add, sub, mul, truediv, floordiv, mod, neg (9 models)
  - `copy`: copy, deepcopy (2 models)
  - `io`: StringIO, BytesIO, read, write, getvalue (5 models)
  - `heapq`: heappush, heappop, heapify, heapreplace, heappushpop, nlargest, nsmallest (7 models)
  - `bisect`: bisect_left, bisect_right, bisect, insort_left, insort_right, insort (6 models)
  - `enum`: Enum, IntEnum, auto, value, name (5 models)
  - `dataclasses`: dataclass, field, asdict, astuple, fields, replace (6 models)

- **Enhanced loop handling**:
  - Smart bound inference from SymbolicRange iterators
  - Induction variable detection (i += step patterns)
  - Loop summarization for closed-form computation
  - Improved loop invariant generation
  - Induction-aware widening with bound constraints

- **State merging improvements**:
  - Linking constraints to preserve condition-value relationships
  - Better precision for single-arm conditionals

### Changed
- Rebranded from "Shadow VM" to "PySpectre" throughout documentation
- Updated CLI to use `pyspectre` command

### Fixed
- Test patterns for symbolic division by zero detection
- State merger precision for merged value constraints

## [0.1.0-alpha] - 2026-01-24

### Added
- Initial release
- Symbolic execution engine with Z3 integration
- Bug detectors: division by zero, assertion errors, index errors, key errors, type errors
- Path exploration strategies: DFS, BFS, coverage-guided
- Output formats: text, JSON, HTML, Markdown, SARIF
- CLI interface
- Full type annotations
