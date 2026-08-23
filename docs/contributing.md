# Contributing to LENSINT

Thank you for your interest in contributing to LENSINT! This guide outlines the development environment setup, code quality standards, and testing procedures.

---

## Development Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yxdooo/lensint.git
   cd lensint
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install Editable Package with Development Dependencies**:
   ```bash
   pip install -e ".[all]"
   ```

---

## Running the Automated Test Suite

We maintain a modular test suite covering all core and forensic modules:

```bash
# Run all tests with verbose output
pytest tests/ -v

# Run tests with code coverage analysis
pytest tests/ --cov=lensint --cov-report=term-missing
```

---

## Code Quality Standards

Before submitting a Pull Request, ensure:
- All 50 unit tests pass.
- Flake8 linting passes without errors:
  ```bash
  flake8 lensint tests
  ```
- Security scanning passes cleanly:
  ```bash
  bandit -r lensint -ll -ii
  ```
