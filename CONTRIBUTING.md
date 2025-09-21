# Contributing to DECOYABLE

Thank you for your interest in contributing to DECOYABLE! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Security](#security)

## Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. By participating, you agree to:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Show empathy towards other contributors
- Help create a positive community

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/decoyable.git
   cd decoyable
   ```
3. **Set up the development environment** (see below)
4. **Create a feature branch** for your changes

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Docker and Docker Compose (for containerized development)
- Git

### Local Development

1. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

2. **Install development dependencies**:
   ```bash
   pip install black isort flake8 mypy pre-commit pytest pytest-cov ruff
   ```

3. **Set up pre-commit hooks**:
   ```bash
   pre-commit install
   ```

4. **Run the application**:
   ```bash
   # CLI mode
   python -m decoyable scan --help

   # API mode
   uvicorn decoyable.api.app:app --reload
   ```

### Docker Development

For containerized development:

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or build and run manually
docker build -f docker/Dockerfile -t decoyable:dev .
docker run -p 8000:8000 decoyable:dev
```

## Development Workflow

### Branch Naming

Use descriptive branch names following this pattern:
- `feature/description-of-feature`
- `fix/description-of-fix`
- `docs/description-of-docs`
- `refactor/description-of-refactor`

### Commit Messages

Follow [Conventional Commits](https://conventionalcommits.org/) format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions/modifications
- `chore`: Maintenance tasks

Examples:
```
feat: add support for custom scan rules
fix: resolve memory leak in dependency scanner
docs: update API documentation
```

### Pull Requests

1. **Ensure your branch is up to date** with main:
   ```bash
   git checkout main
   git pull origin main
   git checkout your-branch
   git rebase main
   ```

2. **Run quality checks**:
   ```bash
   # Run all checks
   pre-commit run --all-files

   # Run tests
   pytest

   # Run type checking
   mypy decoyable/
   ```

3. **Create a pull request** with:
   - Clear title and description
   - Reference to related issues
   - Screenshots/logs for UI changes
   - Testing instructions

## Code Style

This project uses several tools to maintain code quality:

### Formatting
- **Black**: Code formatting (88 character line length)
- **isort**: Import sorting

### Linting
- **Ruff**: Fast Python linter
- **Flake8**: Additional style checks
- **MyPy**: Type checking

### Pre-commit Hooks

Pre-commit hooks automatically run these checks. Install them with:
```bash
pre-commit install
```

Manual formatting:
```bash
black decoyable/ tests/
isort decoyable/ tests/
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=decoyable --cov-report=html

# Run specific test file
pytest tests/test_scanners.py

# Run tests matching pattern
pytest -k "test_secret"
```

### Test Structure

- Unit tests in `tests/` directory
- Test files named `test_*.py`
- Test classes named `Test*`
- Test functions named `test_*`

### Writing Tests

```python
import pytest
from decoyable.scanners.secrets import SecretScanner

class TestSecretScanner:
    def test_detects_api_keys(self):
        scanner = SecretScanner()
        # Test implementation
        assert result == expected
```

## Submitting Changes

1. **Fork and clone** the repository
2. **Create a feature branch** from `main`
3. **Make your changes** following the guidelines above
4. **Run quality checks** and tests
5. **Commit with clear messages**
6. **Push to your fork**
7. **Create a pull request** to the main repository

### Pull Request Requirements

- [ ] Tests pass
- [ ] Code style checks pass
- [ ] Type checking passes
- [ ] Documentation updated (if needed)
- [ ] Changelog updated (if needed)
- [ ] Related issues linked

## Security

See [SECURITY.md](SECURITY.md) for security-related information.

### Security Considerations for Contributors

- Never commit sensitive information (API keys, passwords, etc.)
- Use environment variables for configuration
- Follow secure coding practices
- Report security vulnerabilities responsibly

## Additional Resources

- [Issue Tracker](https://github.com/your-org/decoyable/issues)
- [Documentation](https://decoyable.dev/docs)
- [API Reference](https://decoyable.dev/api)

## Questions?

If you have questions about contributing:

- Check existing [issues](https://github.com/your-org/decoyable/issues) and [discussions](https://github.com/your-org/decoyable/discussions)
- Join our community chat
- Contact the maintainers

Thank you for contributing to DECOYABLE! 🚀
- Do not disclose vulnerabilities in public issues. Email maintainers per SECURITY.md or the repo's contact.

## Synchronization checklist (match with other repo files)
- README links to CONTRIBUTING.md.
- package.json scripts include `test`, `lint`, `build` used here.
- CODE_OF_CONDUCT.md and LICENSE present and referenced.
- .github/ISSUE_TEMPLATE and PULL_REQUEST_TEMPLATE exist and reflect this workflow.
- CI config (e.g., .github/workflows/*) enforces the listed checks.

## Need a tailored version?
Provide the repository tree or key files (package.json, README, CI config, CODE_OF_CONDUCT). The CONTRIBUTING.md will be adjusted to match exact scripts, commands, and policies.

Thank you for contributing.
