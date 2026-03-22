# Contributing to dns-security-auditor

Thanks for your interest in contributing to dns-security-auditor.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/dns-security-auditor.git`
3. Install dependencies: `pip install -r requirements.txt`
4. Run tests: `python -m pytest tests/ -v`

## Development Guidelines

- Follow existing code style and patterns
- Add tests for new scoring logic or DNS checks
- Keep commits descriptive using conventional commit format (`fix:`, `feat:`, `docs:`)
- Update documentation if behavior changes

## Scoring System

The scoring engine (`security_scoring.py`) uses a 100-point scale across 6 categories. Any changes to scoring weights or grade thresholds must be reflected in:
- `security_scoring.py` (source of truth)
- `static/methodology.html` (public documentation)
- `tests/test_scoring.py` (test coverage)

## Submitting Changes

1. Create a feature branch from `main`
2. Make your changes
3. Run the full test suite: `python -m pytest tests/ -v`
4. Open a pull request against `main`

## Reporting Issues

Use GitHub Issues. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
