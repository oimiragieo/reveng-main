# Workflows Directory

## Overview

The `.github/workflows/` directory contains GitHub Actions workflow definitions that automate testing, building, deployment, and quality assurance for the REVENG project.

**Purpose**: Automated CI/CD pipelines for testing, building, and deploying REVENG.

**Location**: `/home/user/reveng-main/.github/workflows/`

## Workflows

### Testing Workflows

**ci.yml** (3,485 bytes) - Continuous Integration
- Runs on every push and PR
- Lints code
- Runs unit tests
- Checks code quality

**test.yml** (3,418 bytes) - Comprehensive Testing
- Unit tests
- Integration tests
- Code coverage reporting
- Multi-Python version testing

**tests.yml** (2,245 bytes) - Additional Test Suites
- E2E tests
- Performance tests
- Security tests

**lint.yml** (1,650 bytes) - Code Quality
- Python linting (pylint, flake8)
- Type checking (mypy)
- Code formatting (black)
- Import sorting (isort)

### Build Workflows

**build.yml** (4,120 bytes) - Build Automation
- Build Python package
- Build documentation
- Create distribution artifacts
- Version validation

**docker.yml** (2,273 bytes) - Docker Image Build
- Build Docker image
- Push to Docker Hub
- Tag with version
- Latest tag update

**docker-multiarch.yml** (1,830 bytes) - Multi-Architecture Docker
- Build for amd64, arm64
- Cross-platform support
- Unified manifest

### Quality & Security

**security.yml** (2,137 bytes) - Security Scanning
- Dependency vulnerability scanning
- SAST (Static Application Security Testing)
- Secret scanning
- License compliance

**docs.yml** (1,939 bytes) - Documentation
- Build MkDocs site
- Deploy to GitHub Pages
- Validate documentation links
- Generate API docs

### Release

**release.yml** (915 bytes) - Release Automation
- Tag-based releases
- Changelog generation
- Asset upload
- PyPI publishing

## Usage

### Viewing Workflow Runs

1. Go to GitHub repository
2. Click "Actions" tab
3. View workflow runs and logs

### Triggering Workflows

**Automatic:**
- Push to any branch → CI, test, lint
- Push to main → All workflows
- Create PR → CI, test
- Create tag → Release workflow

**Manual:**
```bash
# Trigger workflow via GitHub CLI
gh workflow run ci.yml

# Trigger specific workflow
gh workflow run build.yml --ref main
```

### Workflow Status

Check status badges in README:
- Build: ![Build](https://github.com/.../badge.svg)
- Tests: ![Tests](https://github.com/.../badge.svg)
- Coverage: ![Coverage](https://codecov.io/.../badge.svg)

## Notes

### Workflow Matrix

**Python Versions Tested:**
- 3.9
- 3.10
- 3.11
- 3.12

**Operating Systems:**
- ubuntu-latest
- macos-latest
- windows-latest

### Caching

Workflows use caching for:
- pip dependencies
- pytest cache
- Docker layers
- Build artifacts

### Secrets

Required GitHub Secrets:
- `PYPI_TOKEN` - PyPI publishing
- `DOCKER_USERNAME` - Docker Hub
- `DOCKER_PASSWORD` - Docker Hub
- `CODECOV_TOKEN` - Code coverage
- `GEMINI_API_KEY` - AI testing (optional)

---

**Total Workflows**: 10
**Purpose**: Automation and CI/CD
**Triggers**: Push, PR, release, schedule
