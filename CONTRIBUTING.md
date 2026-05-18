# Contributing to pysymex

**pysymex is currently an "Open Source, but Closed Contribution" project.**

### Why?
The engine is currently in a high-velocity alpha stage. To ensure absolute architectural integrity, legal correctness, and consistency in the formal verification logic, the project maintainer is currently the sole author and contributor.

### Can I use the code?
**Yes!** The project is licensed under the **GNU Affero General Public License v3.0**. You are free to run it, study it, and modify it for your own purposes under the terms of that license.

### Can I submit a Pull Request?
**Not at this time.** We are not currently accepting external Pull Requests or code contributions. Any PRs opened will be closed with a reference to this policy.

### How can I help?
While we don't accept code, we highly value your feedback! You can help by:
- **Reporting Bugs:** Open an issue with a minimal reproduction case.
- **Requesting Features:** Share your ideas for new detectors or optimizations.
- **Discussions:** Use the GitHub Discussions tab to ask questions or share how you're using the tool.

---

## Reporting Issues

When filing a bug report, include:

- Python version
- pysymex version or commit
- Operating system
- A minimal reproduction script
- The full traceback or failing command output

## Development Setup (for local study)

```bash
git clone https://github.com/darkoss1/pysymex.git
cd pysymex
uv sync
```

## Local Checks

```bash
# Linting
uv run ruff check .
uv run ruff format pysymex tests

# Type Checking
uv run pyright pysymex tests

# Testing
uv run pytest tests/ -v
```
