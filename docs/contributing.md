# Contributing to LENSINT

This document specifies the development setup, code quality requirements, architectural conventions, and automated testing procedures for contributing to LENSINT.

---

## Development Environment Setup

### 1. Clone the Repository
```bash
git clone https://github.com/yxdooo/lensint.git
cd lensint
```

### 2. Create and Activate a Virtual Environment
```bash
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
```

### 3. Install Package with Full Dependencies
```bash
pip install -e ".[all]"
```

---

## Automated Verification & Testing

Every Pull Request must pass the complete unit, regression, and integration test suite:

```bash
# Run complete test suite
pytest tests/ -v

# Run test suite with code coverage reporting
pytest tests/ --cov=lensint --cov-report=term-missing
```

---

## Engineering Standards & Code Quality

1. **Strict Type Annotations**: All function arguments and return types must be fully type-hinted (`typing` / Python 3.9+ type syntax).
2. **Deterministic Output & Exception Boundaries**: Forensic extractors must handle malformed binary input gracefully without unhandled exceptions or state leaks across worker threads.
3. **No AI Clichés or Marketing Buzzwords**: All documentation, docstrings, and comments must adhere to technical, formal DFIR / IEEE standards in English with zero emojis.
4. **Linting and Static Analysis**:
   ```bash
   # Linting
   flake8 lensint tests

   # Security vulnerability static analysis
   bandit -r lensint -ll -ii
   ```

---

## License

By contributing to LENSINT, you agree that your contributions will be licensed under the project's [MIT License](../LICENSE).
