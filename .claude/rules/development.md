# Development Rules for REVENG

## Code Quality Standards

### Python Code Style
- **PEP 8 Compliance**: All Python code must follow PEP 8 style guide
- **Line Length**: Maximum 100 characters per line
- **Formatting**: Use `black` formatter with `--line-length=100`
- **Import Sorting**: Use `isort` with black-compatible profile
- **Type Hints**: Add type hints to all function signatures (target: 80%+ coverage)
- **Docstrings**: Document all classes, functions, and modules (Google style)

### Code Quality Checks
- **Linting**: Code must pass `flake8`/`pylint` with max-line-length=100
- **Security**: Code must pass `bandit` security scan (level -ll)
- **Architecture contracts**: Code must pass `import-linter` (`.importlinter`, run by `make lint` / `lint-imports --no-cache`). `reveng.core` is the foundation and must not import higher-level domains; `reveng.security` must not import `reveng.ai`/`reveng.agents.ai`. Needs an editable install (`pip install -e .`).
- **Test Coverage**: Keep coverage steady in touched areas (no enforced `fail-under`); add a regression test for every bug fix.
- **No Dead Code**: Remove unused imports, functions, and variables
- **No TODO Comments**: Convert TODOs to GitHub issues before committing

### Pre-commit Hooks
Always run pre-commit hooks before committing:
```bash
pre-commit install
pre-commit run --all-files
```

Hooks include:
- black (formatting)
- isort (import sorting)
- flake8 (linting)
- bandit (security)
- trailing-whitespace
- end-of-file-fixer
- check-yaml
- check-added-large-files

---

## Documentation Standards

### README Files
- Every major directory must have a README.md
- Include purpose, usage, and examples
- Keep examples up-to-date and tested

### Claude.md Files
- Every directory must have a claude.md file for AI assistant context
- Include comprehensive overview, file listings, and usage
- Update when directory structure or purpose changes
- Maintain consistency with root claude.md format

### Code Comments
- Use inline comments for complex logic only
- Prefer self-documenting code over excessive comments
- Update comments when code changes
- Remove outdated or misleading comments

### API Documentation
- All public APIs must be fully documented
- Include parameter descriptions, return types, and examples
- Document exceptions and error conditions
- Keep API docs in sync with code

---

## Testing Requirements

### Test Coverage
- **Minimum Coverage**: 90% (target: 95%)
- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows
- **POC Tests**: Proof-of-concept tests for experimental features

### Test Organization
- Place tests in `tests/` directory
- Mirror source structure in test organization
- Use descriptive test names (test_feature_should_behave_correctly)
- One assertion per test when possible

### Test Execution
```bash
# Run all tests with coverage
pytest tests/ --cov=src/reveng --cov-report=html

# Run specific category
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/e2e/ -v

# Run in parallel
pytest tests/ -n auto
```

### Test Requirements
- All new features must have tests
- Bug fixes must include regression tests
- Tests must be deterministic (no random failures)
- Tests should be fast (<2 minutes for full suite)
- Mock external dependencies (APIs, filesystems, networks)

---

## Git Workflow

### Branch Naming
- Feature branches: `feature/description` or `claude/feature-name-sessionid`
- Bug fixes: `bugfix/issue-number-description`
- Documentation: `docs/description`
- Experimental: `experiment/description`

### Commit Messages
Follow conventional commits format:
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting, missing semi-colons, etc.
- `refactor`: Code restructuring without behavior changes
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples**:
```
feat(ai): add LLM4Decompile integration for 90% recompilability
fix(cli): resolve permission issue with reveng.py executable
docs(api): update API reference with new MCP tools
refactor(core): remove 750 lines of dead legacy code
```

### Pull Request Guidelines
- PRs must have clear description of changes
- Link related issues (#123)
- Include test results and coverage
- Pass all CI checks before requesting review
- Address review comments promptly
- Squash commits when merging (optional, per maintainer preference)

---

## Security Requirements

### Secrets Management
- **Never commit secrets**: API keys, passwords, tokens
- **Use environment variables**: For all sensitive configuration
- **Use .gitignore**: Ensure secrets files are ignored
- **Rotate keys regularly**: Update API keys every 90 days
- **Principle of least privilege**: Minimize permissions

### Security Scanning
Run security scans before committing:
```bash
# Python dependency vulnerabilities
safety check

# Python code vulnerabilities
bandit -r src/ -ll

# Comprehensive audit
pip-audit
```

### Vulnerability Disclosure
- Report vulnerabilities via SECURITY.md process
- Do not disclose publicly before fix
- Allow 90 days for coordinated disclosure
- Follow responsible disclosure guidelines

---

## Performance Standards

### Code Performance
- **Optimize for readability first**: Then optimize if needed
- **Profile before optimizing**: Use cProfile or line_profiler
- **Avoid premature optimization**: Focus on algorithmic improvements
- **Cache when beneficial**: Use intelligent caching for expensive operations
- **GPU acceleration**: Use for batch operations when available

### Resource Management
- **Memory efficiency**: Avoid loading entire files into memory when possible
- **File handles**: Always close file handles (use context managers)
- **Network connections**: Pool connections, implement timeouts
- **CPU usage**: Multi-threading for I/O, multiprocessing for CPU-bound tasks
- **Disk I/O**: Batch operations when possible

### Performance Targets
- Small binary analysis: <10 seconds
- Medium binary (1-10MB): <30 seconds
- Large binary (10-100MB): <3 minutes
- MCP tool response: <2 seconds average
- Cache hit rate: >80%

---

## Architecture Principles

### Design Philosophy
- **Simplicity**: Prefer simple solutions over complex ones
- **Modularity**: Design components to be independent and reusable
- **Extensibility**: Make it easy to add new features
- **Testability**: Design for easy testing from the start
- **Documentation**: Code should be self-documenting when possible

### Code Organization
- **Single Responsibility**: Each module/class should have one clear purpose
- **DRY (Don't Repeat Yourself)**: Extract common code into reusable functions
- **Layered domains**: `reveng.core` (foundation) → analysis/intelligence/orchestration domains → entrypoints (`reveng.cli`, MCP). Dependencies point downward toward `core`; never import upward. The `ai`↔`security` cycle is broken (shared models live in `reveng.core.ai_models`) and locked by an import-linter contract — keep it that way.
- **Separation of Concerns**: Keep UI, business logic, and data layers separate
- **Dependency Injection**: Pass dependencies rather than hardcoding them (e.g. the VRL `IterativeRefiner` takes analyzer/compile_fn/oracle_factory)
- **Configuration over Code**: Use configuration files for flexibility

### Error Handling
- **Fail Fast**: Catch errors early and provide clear messages
- **Informative Errors**: Error messages should guide users to solutions
- **Graceful Degradation**: Provide fallback behavior when possible
- **Logging**: Log errors with context (file, line, stack trace)
- **User-Friendly**: Technical errors should have user-friendly explanations

---

## AI Assistant Guidelines

### When Working with AI Assistants (Claude, etc.)

#### Code Generation
- Review all AI-generated code carefully
- Test generated code thoroughly
- Ensure generated code follows project standards
- Add appropriate comments and documentation
- Verify security implications

#### Documentation
- AI can help generate documentation templates
- Always review and customize AI-generated docs
- Ensure accuracy and completeness
- Maintain consistent tone and style

#### Code Review
- Use AI for preliminary code review
- Human review is still required
- AI suggestions are recommendations, not requirements
- Question AI reasoning when uncertain

### Claude.md Files
- Keep claude.md files up-to-date for AI context
- Include comprehensive project information
- Document architecture and design decisions
- Provide clear examples and usage patterns
- Update after significant changes

---

## Continuous Integration

### GitHub Actions
All commits must pass CI checks:
- Linting (flake8)
- Formatting (black check)
- Security scanning (bandit)
- Tests (pytest with ≥90% coverage)
- Build verification
- Documentation build (if applicable)

### Pre-merge Requirements
Before merging to main:
- ✅ All tests passing
- ✅ Code coverage ≥90%
- ✅ All linters passing
- ✅ Security scan clean
- ✅ Documentation updated
- ✅ Changelog updated (if applicable)
- ✅ Review approved

---

## Release Process

### Version Numbering (SemVer)
- **MAJOR**: Breaking changes (e.g., 4.0.0 → 5.0.0)
- **MINOR**: New features, backwards-compatible (e.g., 4.0.0 → 4.1.0)
- **PATCH**: Bug fixes (e.g., 4.0.0 → 4.0.1)

### Release Checklist
- [ ] All tests passing (≥90% coverage)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] VERSION file updated
- [ ] Security scan clean
- [ ] Performance benchmarks met
- [ ] Example code tested
- [ ] Breaking changes documented
- [ ] Migration guide (if needed)
- [ ] Tag release in git
- [ ] Build and publish packages
- [ ] Announce release

---

## Code Review Checklist

### For Authors
Before requesting review:
- [ ] Code follows style guide (black, isort, flake8)
- [ ] Tests written and passing
- [ ] Documentation updated
- [ ] No debugging code (print statements, breakpoints)
- [ ] No commented-out code
- [ ] Commit messages are clear and descriptive
- [ ] PR description explains changes

### For Reviewers
When reviewing code:
- [ ] Code is readable and maintainable
- [ ] Logic is correct and efficient
- [ ] Edge cases are handled
- [ ] Error handling is appropriate
- [ ] Tests are comprehensive
- [ ] Documentation is accurate
- [ ] Security considerations addressed
- [ ] Performance implications considered

---

## Common Pitfalls to Avoid

### Code Quality
- ❌ Long functions (>50 lines typically too long)
- ❌ Deep nesting (>3 levels indicates complexity)
- ❌ Magic numbers (use named constants)
- ❌ Broad exception catching (except Exception: or except:)
- ❌ Mutable default arguments (def func(list=[]):)

### Performance
- ❌ Loading entire files into memory
- ❌ N+1 query problems
- ❌ Unnecessary copying of large objects
- ❌ Blocking I/O in async functions
- ❌ Not using generators for large datasets

### Security
- ❌ SQL injection vulnerabilities
- ❌ Command injection (shell=True without validation)
- ❌ Path traversal vulnerabilities
- ❌ Hardcoded credentials
- ❌ Insecure deserialization (pickle from untrusted sources)

### Testing
- ❌ Tests that depend on external services
- ❌ Tests that depend on test execution order
- ❌ Tests with random failures
- ❌ Tests without assertions
- ❌ Integration tests without proper cleanup

---

## Resources

### Official Documentation
- [Python Style Guide (PEP 8)](https://www.python.org/dev/peps/pep-0008/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)

### Project Documentation
- **Contributing Guide**: `CONTRIBUTING.md`
- **Code of Conduct**: `CODE_OF_CONDUCT.md`
- **Security Policy**: `SECURITY.md`
- **Developer Guide**: `docs/developer-guide/claude.md`
- **Architecture Docs**: `docs/architecture/claude.md`

### Tools
- **black**: Code formatter
- **isort**: Import sorter
- **flake8**: Linter
- **pylint**: Advanced linter
- **bandit**: Security scanner
- **pytest**: Testing framework
- **pytest-cov**: Coverage reporting
- **pre-commit**: Git hook framework

---

**Remember**: These rules exist to maintain code quality, consistency, and collaboration efficiency. When in doubt, ask for clarification or discuss exceptions with maintainers.
