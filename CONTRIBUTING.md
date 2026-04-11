# Contributing to PySyMex

Thanks for your interest in contributing to PySyMex.

## Development Setup

```bash
git clone https://github.com/darkoss1/pysymex.git
cd pysymex
python -m venv .venv
```

Activate the virtual environment:

- Windows PowerShell: `.venv\\Scripts\\Activate.ps1`
- Windows CMD: `.venv\\Scripts\\activate.bat`
- macOS/Linux: `source .venv/bin/activate`

Install development dependencies:

```bash
pip install -e ".[dev]"
```

## Local Checks

Format the code:

```bash
ruff format pysymex tests
```

Run strict type checking:

```bash
pyright pysymex
```

Run tests:

```bash
pytest tests/ -v
```

Coverage run:

```bash
pytest tests/ -v --cov=pysymex --cov-report=xml --cov-branch
```

## Contribution Guidelines

- Keep changes focused and easy to review.
- Add or update tests for behavior changes.
- Place unit tests in the shadow tree under `tests/unit/...` mirroring `pysymex/...` module paths.
- Legacy tests are archived under `tests_backup/` and are excluded from default discovery.
- Update docs when public behavior or workflows change.
- Follow the existing formatting and typing standards.
- Prefer small, descriptive commits and pull requests.

## Pull Requests

Before opening a pull request, try to make sure these pass locally:

- `ruff format pysymex tests`
- `pyright pysymex`
- `pytest tests/ -v`

## Reporting Issues

When filing a bug report, include:

- Python version
- PySyMex version or commit
- operating system
- a minimal reproduction
- the full traceback or failing command output

## Related Docs

- [README.md](README.md)
- [docs/contributing.rst](docs/contributing.rst)
