# pysymex

<div align="center">

**python symbolic execution and formal verification research engine**

Bytecode-level path exploration for supported Python programs, backed by Z3 and explicit
unknown, unsupported, inconclusive, and blocked states when a definite answer is not justified.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-2563eb.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-alpha_0.1.1a1-f59e0b.svg)](https://github.com/darkoss1/pysymex)
[![Solver](https://img.shields.io/badge/solver-Z3-7c3aed.svg)](https://github.com/Z3Prover/z3)
[![License](https://img.shields.io/badge/license-AGPL--3.0--only-111827.svg)](LICENSE)

</div>

---

> [!WARNING]
> pysymex is an alpha research prototype for studying symbolic execution and formal
> verification concepts. It is not production verification software, a security audit
> substitute, or a guarantee that a target program is safe.

## At a Glance

| Area | Current focus |
| --- | --- |
| Execution model | CPython bytecode execution for Python 3.11 through 3.13 |
| Reasoning engine | Z3-backed path constraints and feasibility checks |
| Result model | Definite issues only when the path is feasible; uncertainty remains explicit |
| Output formats | Text, JSON, Markdown, HTML, and SARIF |
| Primary interfaces | `pysymex scan`, `pysymex analyze`, `pysymex verify`, and Python APIs |
| Project phase | Alpha, research-oriented, closed to external pull requests |

## Install

Use Python 3.11 or newer.

```bash
pip install pysymex
```

For local development from this repository:

```bash
git clone https://github.com/darkoss1/pysymex.git
cd pysymex
uv sync
```

`uv sync` creates `.venv` and sets the shell activation prompt to the project
name (`pysymex`). Prefer `uv sync` over bare `uv venv` for first-time setup.

Core runtime dependencies are pinned or constrained in [pyproject.toml](pyproject.toml),
including `z3-solver`, `pydantic`, `immutables`, `rich`, and `psutil`.

## Quick Start

Scan a file:

```bash
pysymex scan mycode.py
```

Scan a directory recursively:

```bash
pysymex scan src/ -r
```

Generate SARIF for CI systems:

```bash
pysymex scan src/ -r --format sarif -o report.sarif
```

Analyze a specific function:

```bash
pysymex analyze mycode.py -f risky_divide --args x:int y:int
```

Run the benchmark command:

```bash
pysymex benchmark --format markdown
```

## Command Map

| Need | Interface |
| --- | --- |
| Scan a file or tree for supported issue patterns | `pysymex scan PATH [-r]` |
| Inspect one function with typed symbolic inputs | `pysymex analyze FILE -f NAME --args x:int` |
| Verify contract-decorated code | `pysymex verify FILE -f NAME` |
| Fail a CI job by severity and optionally write SARIF | `pysymex check PATH --fail-on high --sarif report.sarif` |
| Measure benchmark cases or compare baselines | `pysymex benchmark [--case NAME]` |

## Python API

```python
import asyncio

from pysymex import analyze


def risky_divide(x: int, y: int) -> int:
    return x // y


result = asyncio.run(analyze(risky_divide, {"x": "int", "y": "int"}))

for issue in result.issues:
    print(issue.kind)
    print(issue.message)
    print(issue.get_counterexample())
```

Use the Python API when you want direct access to symbolic execution results. Use the CLI when
you want scanner workflows, report files, or CI-friendly output.

## Supported Inputs and Reports

| Surface | Current support |
| --- | --- |
| Python versions | CPython 3.11, 3.12, and 3.13 bytecode families |
| CLI symbolic argument types | `int`, `str`, `list`, `bool`, and `dict` |
| Scan | Symbolic execution only (`pysymex scan`; static/pipeline modes removed) |
| Report formats | `text`, `json`, `sarif`, `rich`, `html`, and `markdown` |
| CI workflow | `pysymex check` for severity-gated exits; SARIF for external viewers |
| Sandbox boundary | Target loading can go through the sandbox bridge; denials remain visible |

## Result Semantics

pysymex should not turn uncertainty into success. A result can include definite issues,
unsupported behavior, blocked execution, or inconclusive paths depending on what the engine can
justify.

| State | Meaning |
| --- | --- |
| Definite issue | A feasible path reaches a detector condition or runtime failure |
| No issue reported | No definite issue was found within the explored supported paths |
| Unsupported | The target used behavior outside the implemented semantic model |
| Unknown or inconclusive | Solver uncertainty, path limits, incomplete modeling, or other limits prevented a definite answer |
| Blocked | Isolation, import, sandbox, or environment policy prevented execution |

## Practical Boundaries

| Boundary | What it means for users |
| --- | --- |
| Feasibility first | A definite bug report should correspond to a feasible path, not just a syntactic pattern |
| Bounded exploration | Timeouts, path limits, and iteration limits can leave reachable behavior unexplored |
| Model coverage | Builtins, stdlib calls, imports, and dynamic Python features are only as precise as their models |
| Solver uncertainty | Z3 `unknown`, timeouts, or encoding gaps must remain inconclusive instead of becoming success |
| Sandbox policy | Native isolation and sandbox bridge failures are blocked states, not proof that code is safe |
| Report confidence | JSON, SARIF, HTML, and Markdown change presentation, not the underlying certainty level |

## Detection Surface

The detector surface includes runtime failures and static or logical signals. Coverage depends on
supported syntax, bytecode, models, path limits, and solver outcomes.

| Family | Examples |
| --- | --- |
| Arithmetic | division by zero, modulo by zero, overflow |
| Containers | index error, key error, missing attributes, symbolic container access |
| Runtime state | unbound local, name error, type error, value error, none dereference |
| Control flow | assertion failure, unreachable code, infinite loop signals |
| Resources | resource leak patterns |
| Contracts | precondition, postcondition, and contract validation failures |
| Logical checks | contradictions, impossible branches, path-level inconsistencies |

## Architecture

```text
pysymex/
  api/                  public Python API facade
  cli/                  command-line interface and formatters
  scanner/              file and directory scanning workflows
  execution/            symbolic VM, opcode dispatch, and execution strategies
  core/                 symbolic state, memory, solver, and shared types
  models/               builtin, stdlib, and runtime behavior models
  analysis/             detectors, scanner range checks, and higher-level analyses
  sandbox/              isolation-facing execution boundaries
  reporting/            text, JSON, Markdown, HTML, and SARIF report generation
  tracing/              Z3 and execution trace support
```

The important boundary is trust: execution, solver, scanner, model, sandbox, and reporting layers
should keep unsupported or inconclusive behavior visible instead of silently treating it as a
successful verification result.

## Examples

The [examples](examples) directory contains small, numbered scenarios:

| File | Focus |
| --- | --- |
| `01_basic_safety_guards.py` | Basic guard patterns |
| `02_common_runtime_bugs.py` | Common runtime failures |
| `03_hidden_branch_constraints.py` | Nested branches found via symbolic scan |
| `04_contract_verification.py` | Contract checking |
| `05_deep_path_loops.py` | Loop and path-depth behavior |
| `06_sandbox_security.py` | Sandbox-oriented examples |
| `07_symbolic_containers.py` | Symbolic container behavior |
| `08_exception_handling.py` | Exception paths |

## Development

Use the locked `uv` workflow when possible:

```bash
uv sync
uv run ruff check pysymex tests
uv run pyright pysymex tests
uv run pytest
```

Run a focused test while iterating:

```bash
uv run pytest tests/unit/path/to/test_file.py -q
```

Run multi-version Docker validation through the one-click script:

```bash
python tests/docker.py -- -q
```

## Documentation

| Document | Purpose |
| --- | --- |
| [docs/README.md](docs/README.md) | Documentation index and recommended read order |
| [docs/API.md](docs/API.md) | Public Python API reference |
| [docs/CLI.md](docs/CLI.md) | Command-line usage and examples |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Supported scope, uncertainty states, and safety boundaries |
| [docs/arch/README.md](docs/arch/README.md) | Source-grounded architecture reference |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | Terms used across the project |

An automatically generated Code Wiki is also available for exploratory architecture browsing:
[deepwiki.com/darkoss1/pysymex/](https://deepwiki.com/darkoss1/pysymex/).
Treat it as secondary material that may lag behind this repository.

## Contribution Policy

pysymex is currently open source but closed to external pull requests during its alpha phase.
Issues and bug reports are welcome through the repository issue tracker.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the current policy.

## License

pysymex is licensed under the [AGPL-3.0-only](LICENSE).

---

<div align="center">

Research engine. Explicit uncertainty. Feasible bugs over optimistic claims.

</div>
