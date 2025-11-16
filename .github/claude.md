# .github Directory

## Overview

The `.github/` directory contains GitHub-specific configuration files including CI/CD workflows, issue templates, and pull request templates. This directory configures GitHub Actions automation and community templates.

**Purpose**: GitHub configuration including CI/CD, issue templates, and community files.

**Location**: `/home/user/reveng-main/.github/`

## Directory Contents

```
.github/
├── claude.md                      # This file
│
├── workflows/                     # GitHub Actions workflows
│   ├── claude.md
│   ├── build.yml                  # Build workflow (4,120 bytes)
│   ├── ci.yml                     # Continuous integration (3,485 bytes)
│   ├── test.yml                   # Test workflow (3,418 bytes)
│   ├── tests.yml                  # Additional tests (2,245 bytes)
│   ├── lint.yml                   # Code linting (1,650 bytes)
│   ├── security.yml               # Security scanning (2,137 bytes)
│   ├── docs.yml                   # Documentation build (1,939 bytes)
│   ├── docker.yml                 # Docker build (2,273 bytes)
│   ├── docker-multiarch.yml       # Multi-arch Docker (1,830 bytes)
│   └── release.yml                # Release automation (915 bytes)
│
└── ISSUE_TEMPLATE/                # Issue templates
    ├── claude.md
    ├── config.yml                 # Template configuration (510 bytes)
    ├── bug_report.md              # Bug report template (1,259 bytes)
    ├── bug_report.yml             # Bug report form (2,951 bytes)
    ├── feature_request.md         # Feature request template (1,807 bytes)
    ├── feature_request.yml        # Feature request form (2,619 bytes)
    ├── question.md                # Question template (1,022 bytes)
    ├── question.yml               # Question form (1,762 bytes)
    └── security_report.md         # Security report template (1,419 bytes)
```

## Structure

### Workflows (CI/CD)

GitHub Actions workflows automate testing, building, and deployment:

**Testing Workflows:**
- **ci.yml** - Continuous integration pipeline
- **test.yml** - Automated test execution
- **tests.yml** - Additional test suites
- **lint.yml** - Code quality and linting

**Build Workflows:**
- **build.yml** - Build automation
- **docker.yml** - Docker image builds
- **docker-multiarch.yml** - Multi-architecture Docker builds

**Quality & Security:**
- **security.yml** - Security scanning (SAST, dependency check)
- **docs.yml** - Documentation build and deploy

**Release:**
- **release.yml** - Release automation

### Issue Templates

Standardized templates for GitHub issues:

**Bug Reports:**
- **bug_report.md** - Markdown template
- **bug_report.yml** - Form template

**Feature Requests:**
- **feature_request.md** - Markdown template
- **feature_request.yml** - Form template

**Questions:**
- **question.md** - Markdown template
- **question.yml** - Form template

**Security:**
- **security_report.md** - Security vulnerability reports

**Configuration:**
- **config.yml** - Issue template configuration

## Usage

### CI/CD Workflows

Workflows run automatically on:
- **Push**: Build, test, lint
- **Pull Request**: Full CI pipeline
- **Release**: Build and deploy
- **Schedule**: Nightly security scans

### Creating Issues

Users can create issues using templates:
1. Go to GitHub Issues
2. Click "New Issue"
3. Select appropriate template
4. Fill out template fields
5. Submit issue

### Modifying Workflows

```yaml
# Example workflow modification
# .github/workflows/custom.yml
name: Custom Workflow
on:
  push:
    branches: [main]
jobs:
  custom_job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run custom task
        run: echo "Custom task"
```

## Related Documentation

- **GitHub Actions Docs**: https://docs.github.com/actions
- **Workflow Syntax**: https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions
- **Issue Templates**: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests

## Notes

### Workflow Triggers

**Common Triggers:**
- `on: push` - Every commit
- `on: pull_request` - PRs opened/updated
- `on: schedule` - Cron-based schedules
- `on: release` - Release published
- `on: workflow_dispatch` - Manual trigger

### Best Practices

**Workflows:**
- Use caching for dependencies
- Fail fast for quick feedback
- Use matrix builds for multi-version testing
- Store secrets in GitHub Secrets
- Use concurrency limits

**Issue Templates:**
- Keep templates concise
- Request essential information only
- Provide clear instructions
- Include examples
- Use form validation

---

**Purpose**: GitHub automation and templates
**Workflows**: 10 CI/CD workflows
**Templates**: 4 issue template types
**Automation**: Build, test, deploy, security
