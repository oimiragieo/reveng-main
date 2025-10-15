# REVENG Makefile
# Build automation and development tasks

.PHONY: help install install-dev test test-unit test-integration test-e2e test-performance lint format clean build docker-build docker-run docs serve

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
	pre-commit install

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

# Code Quality
lint:
	black --check src/ tests/
	isort --check-only src/ tests/
	pylint src/
	mypy src/
	yamllint .
	hadolint Dockerfile

format:
	black src/ tests/
	isort src/ tests/

# Build
build:
	python -m build

docker-build:
	docker build -t reveng/cli:latest .
	docker build -t reveng/web:latest -f web_interface/Dockerfile.frontend ./web_interface
	docker build -t reveng/backend:latest -f web_interface/Dockerfile.backend ./web_interface
	docker build -t reveng/ai-service:latest -f web_interface/Dockerfile.ai-service ./web_interface
	docker build -t reveng/worker:latest -f web_interface/Dockerfile.worker ./web_interface

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
