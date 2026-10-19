.PHONY: help install test cov lint format type report clean

PYTHON ?= python3

help:
	@echo "install  install the package with dev extras"
	@echo "test     run the full test suite"
	@echo "cov      run tests with a terminal and HTML coverage report"
	@echo "lint     ruff check + format check + mypy"
	@echo "format   auto-format and auto-fix"
	@echo "report   generate the Allure report into reports/allure-report"
	@echo "clean    remove caches and generated artifacts"

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

cov:
	$(PYTHON) -m pytest --cov=doipbench --cov-report=term-missing --cov-report=html

lint:
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m ruff format --check src tests
	$(PYTHON) -m mypy

format:
	$(PYTHON) -m ruff check src tests --fix
	$(PYTHON) -m ruff format src tests

report:
	$(PYTHON) -m pytest --alluredir=reports/allure-results
	allure generate reports/allure-results -o reports/allure-report --clean

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml reports/allure-results
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
