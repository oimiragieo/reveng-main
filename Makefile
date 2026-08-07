# REVENG Makefile
# Build automation and development tasks

.PHONY: help install install-dev test test-unit test-integration test-e2e test-performance test-poc lint format clean build docker-build docker-run docs serve provision-ga-assets benchmark-source benchmark-source-ga benchmark-bun benchmark-bun-ga app-corpus app-corpus-ga verify-ga-baseline verify-ga-target verify-equivalence-honesty skip-inventory release-report

# Default target
help:
	@echo "REVENG Development Commands"
	@echo "=========================="
	@echo ""
	@echo "Installation:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  test              Run all tests"
	@echo "  test-unit         Run unit tests"
	@echo "  test-integration  Run integration tests"
	@echo "  test-e2e          Run end-to-end tests"
	@echo "  test-performance  Run performance tests"
	@echo "  test-poc          Run optional environment-heavy POC tests"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint      Run linting checks"
	@echo "  format    Format code with black and isort"
	@echo ""
	@echo "Build:"
	@echo "  build         Build Python package"
	@echo "  docker-build  Build Docker images"
	@echo "  docker-run    Run Docker containers"
	@echo ""
	@echo "Release Gates:"
	@echo "  provision-ga-assets  Download/clone public assets used by the strict GA audit path"
	@echo "  benchmark-source    Run tracked native source-vs-binary benchmark report"
	@echo "  benchmark-source-ga Run strict GA native benchmark report"
	@echo "  benchmark-bun       Run tracked Bun sample matrix report"
	@echo "  benchmark-bun-ga    Run strict GA Bun sample matrix"
	@echo "  app-corpus          Generate fixtures and run app reverse-engineering corpus"
	@echo "  app-corpus-ga       Run strict GA app reverse-engineering corpus"
	@echo "  skip-inventory      Generate the skipped-test inventory artifacts"
	@echo "  release-report      Generate the machine-readable and Markdown release report"
	@echo "  verify-ga-baseline  Verify current baseline release gates"
	@echo "  verify-ga-target    Audit strict GA gates against tracked reports"
	@echo ""
	@echo "Documentation:"
	@echo "  docs    Build documentation"
	@echo "  serve   Start development server"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean  Clean build artifacts"

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pip install -r requirements-java.txt

# Testing
test:
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term

test-unit:
	pytest tests/unit/ -v --cov=src --cov-report=html --cov-report=term

test-integration:
	pytest tests/integration/ -v --cov=src --cov-report=html --cov-report=term

test-e2e:
	pytest tests/e2e/ -v --timeout=300

test-performance:
	pytest tests/performance/ -v --timeout=600

test-poc:
	python -m pytest tests/poc/ -m "poc and requires_external_tools" -v

# Code Quality
lint:
	black --check src/ tests/
	isort --check-only src/ tests/
	pylint src/
	mypy src/
	lint-imports --no-cache
	hadolint Dockerfile

format:
	black src/ tests/
	isort src/ tests/

# Build
build:
	python -m build

provision-ga-assets:
	python scripts/provision_ga_assets.py --output reports/ga_asset_provisioning_report.json

benchmark-source:
	python scripts/run_source_binary_benchmark.py

benchmark-source-ga:
	python scripts/run_source_binary_benchmark.py --config .reveng/source_binary_benchmarks.ga.json --output reports/source_binary_benchmarks_report.json

benchmark-bun:
	python scripts/run_bun_sample_matrix.py

benchmark-bun-ga:
	python scripts/run_bun_sample_matrix.py --config .reveng/bun_sample_matrix.ga.json --output reports/bun_sample_matrix.json

app-corpus:
	python scripts/generate_app_corpus_fixtures.py
	python scripts/run_app_reverse_engineering_corpus.py --output reports/app_reverse_engineering_corpus_report.json

app-corpus-ga:
	python scripts/generate_app_corpus_fixtures.py
	python scripts/run_app_reverse_engineering_corpus.py --config .reveng/app_reverse_engineering_corpus.ga.json --output reports/app_reverse_engineering_corpus_report.json

skip-inventory:
	python scripts/generate_skip_inventory.py --json-output reports/skip_inventory.json --markdown-output reports/skip_inventory.md

release-report:
	python scripts/generate_release_report.py --json-output reports/release_report.json --markdown-output reports/release_report.md

verify-ga-baseline:
	python scripts/verify_ga_readiness.py --profile baseline --output reports/ga_readiness_baseline.json

# Phase 5 thin equivalence honesty (fail-closed; not full nightly corpus).
verify-equivalence-honesty:
	/usr/bin/python3.9 scripts/verify_equivalence_honesty.py --emit-report
	/usr/bin/python3.9 scripts/verify_equivalence_honesty.py

verify-ga-target:
	python scripts/provision_ga_assets.py --output reports/ga_asset_provisioning_report.json
	python scripts/generate_app_corpus_fixtures.py
	python scripts/run_app_reverse_engineering_corpus.py --config .reveng/app_reverse_engineering_corpus.ga.json --output reports/app_reverse_engineering_corpus_report.json
	python scripts/run_source_binary_benchmark.py --config .reveng/source_binary_benchmarks.ga.json --output reports/source_binary_benchmarks_report.json
	python scripts/run_bun_sample_matrix.py --config .reveng/bun_sample_matrix.ga.json --output reports/bun_sample_matrix.json
	python scripts/generate_skip_inventory.py --json-output reports/skip_inventory.json --markdown-output reports/skip_inventory.md
	python scripts/verify_ga_readiness.py --profile ga --output reports/ga_readiness_target.json
	python scripts/generate_release_report.py --json-output reports/release_report.json --markdown-output reports/release_report.md

docker-build:
	docker build -t reveng/cli:latest .

docker-run:
	docker-compose up -d

# Documentation
docs:
	mkdocs build

serve:
	mkdocs serve

# Cleanup
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf site/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
