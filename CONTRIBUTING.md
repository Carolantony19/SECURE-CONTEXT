# Contributing to SecretGuard AI

Thank you for your interest in contributing! This guide will help you
get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/Carolantony19/SECURE-CONTEXT.git
cd SECURE-CONTEXT

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Verify
secretguard --version
pytest tests/ -v
```

## Running Tests

```bash
# All tests
pytest tests/ -v

# Unit tests only
pytest tests/unit/ -v

# Integration tests only (creates real git repos)
pytest tests/integration/ -v -m integration

# With coverage
pytest tests/ --cov=secretguard --cov-report=term-missing
```

## Code Guidelines

1. **Type hints**: All functions must have type annotations.
2. **Docstrings**: Use Google-style docstrings for public functions.
3. **Tests**: Every new feature must include unit tests. Aim for 80%+ coverage.
4. **Fake secrets only**: All test data must use clearly synthetic credentials
   (e.g., `sk-fake000...`). **Never** use realistic production key formats.
5. **Cross-platform**: Test on Windows, macOS, and Linux. Use `pathlib.Path`
   instead of string concatenation for file paths.

## Pull Request Process

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for new functionality.
4. Ensure all tests pass: `pytest tests/ -v`
5. Run the scan on your changes: `secretguard scan .`
6. Submit a pull request with a clear description.

## Reporting Bugs

Please open a GitHub Issue with:
- Python version (`python --version`)
- OS and version
- Steps to reproduce
- Expected vs. actual behaviour
- Relevant error output

## Adding Custom Rules

See [docs/configuration.md](docs/configuration.md) for details on adding
custom regex rules via `secretguard.toml`.
