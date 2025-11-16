# 🚀 Start Here - REVENG Quick Navigation Guide

**New to REVENG?** This page will guide you to the right documentation.

---

## 📋 Quick Decision Tree

### I want to...

#### ✅ **Get started in 5 minutes**
→ Go to: [`QUICK_START.md`](QUICK_START.md)
- One-command installation
- First analysis in minutes
- No configuration needed

#### 📚 **Understand what REVENG does**
→ Go to: [`README.md`](README.md)
- Feature overview
- Use cases
- Architecture diagram
- Comparison with other tools

#### 🔧 **Install REVENG properly (with all features)**
→ Go to: [`docs/getting-started/installation.md`](docs/getting-started/installation.md)
- System requirements
- Step-by-step installation
- Optional components (Ghidra, AI APIs)
- Troubleshooting

#### 🎓 **Learn how to use REVENG**
→ Start with: `examples/my_first_analysis.py`
Then read: [`CLI_REFERENCE.md`](CLI_REFERENCE.md)
- All CLI commands
- Examples by use case
- Configuration options

#### 🤖 **Use REVENG with AI agents (Claude, GPT-4)**
→ Go to: [`docs/mcp/README.md`](docs/mcp/README.md)
- MCP server setup
- Claude Desktop integration
- Natural language analysis
- 15+ specialized tools

#### 🐛 **Fix installation or runtime problems**
→ Go to: [`docs/getting-started/troubleshooting.md`](docs/getting-started/troubleshooting.md)
- Common errors and solutions
- Platform-specific issues
- Known bugs and workarounds

#### 🔬 **Deobfuscate JavaScript code**
→ Go to: [`src/reveng/javascript/README.md`](src/reveng/javascript/README.md)
- 10-stage deobfuscation pipeline
- Malware detection
- ML-powered renaming
- Batch processing

#### 👨‍💻 **Contribute to REVENG**
→ Go to: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Development setup
- Code style guide
- Testing requirements
- Pull request process

#### 🔒 **Report security vulnerabilities**
→ Go to: [`SECURITY.md`](SECURITY.md)
- Responsible disclosure policy
- Security contact info
- Bug bounty program

---

## 📖 Documentation Map

### Essential (Start Here)
1. [`README.md`](README.md) - Project overview
2. [`QUICK_START.md`](QUICK_START.md) - 5-minute setup
3. [`docs/getting-started/installation.md`](docs/getting-started/installation.md) - Full installation guide
4. [`CLI_REFERENCE.md`](CLI_REFERENCE.md) - Command reference

### Advanced Features
5. [`docs/mcp/README.md`](docs/mcp/README.md) - AI/MCP integration
6. [`src/reveng/javascript/README.md`](src/reveng/javascript/README.md) - JavaScript deobfuscation
7. [`docs/api/API_REFERENCE.md`](docs/api/API_REFERENCE.md) - Python API

### Reference
8. [`docs/architecture/`](docs/architecture/) - Technical architecture
9. [`docs/guides/`](docs/guides/) - Detailed guides
10. [`docs/index.md`](docs/index.md) - Complete documentation index

---

## 🎯 Common User Journeys

### Journey 1: First-Time User
```
1. Read README.md (5 min) → Understand what REVENG is
2. Run QUICK_START.md (2 min) → Install and verify
3. Run examples/my_first_analysis.py (2 min) → See it work
4. Read CLI_REFERENCE.md (10 min) → Learn commands
5. Analyze your first binary (5 min) → Get results!
```
**Total time:** ~25 minutes to first successful analysis

### Journey 2: AI/Agent Integration
```
1. Read docs/mcp/README.md (10 min) → Understand MCP
2. Run ./reveng-mcp-server (1 min) → Start server
3. Configure Claude Desktop (5 min) → Connect AI
4. Try natural language queries (5 min) → "Analyze this binary..."
```
**Total time:** ~20 minutes to AI-powered analysis

### Journey 3: JavaScript Security Researcher
```
1. Read src/reveng/javascript/README.md (10 min)
2. Run ./reveng-js deobfuscate (1 min) → Test on sample
3. Try malware detection (5 min) → Scan suspicious files
4. Batch process samples (10 min) → Automate workflow
```
**Total time:** ~25 minutes to production workflow

---

## ⚠️ Important Notes

### Documentation Structure Change (Nov 2025)
We recently reorganized documentation. If you're looking for:

- **Installation guide:** Use `docs/getting-started/installation.md` (not root `INSTALLATION.md`)
- **Quick start:** Use `QUICK_START.md` in root (canonical version)
- **Getting started:** Use `docs/getting-started/` directory

Root-level documentation files may be outdated. Always prefer `docs/` versions for detailed guides.

### Version Information
- **Current Version:** 4.0.0 (Production/Stable)
- **Release Date:** November 2025
- **Major Features:** MCP integration, JavaScript deobfuscation, GPU acceleration

---

## 🆘 Getting Help

### Quick Help
```bash
# CLI help
reveng --help
reveng analyze --help
./reveng-js --help
./reveng-mcp-server --help
```

### Documentation
- **FAQ:** [`docs/FAQ.md`](docs/FAQ.md) - Comprehensive FAQ with 40+ questions
- **Troubleshooting:** [`docs/getting-started/troubleshooting.md`](docs/getting-started/troubleshooting.md)
- **API Docs:** [`docs/api/API_REFERENCE.md`](docs/api/API_REFERENCE.md)

### Community
- **Issues:** https://github.com/oimiragieo/reveng-main/issues
- **Discussions:** https://github.com/oimiragieo/reveng-main/discussions
- **Email:** contact@reveng-project.org

---

## 🎉 Ready to Start?

### Complete Beginners
**Start here:** [`QUICK_START.md`](QUICK_START.md) → Get REVENG running in 2 minutes

### Experienced Users
**Jump to:** [`CLI_REFERENCE.md`](CLI_REFERENCE.md) → See all commands and examples

### AI Developers
**Go to:** [`docs/mcp/README.md`](docs/mcp/README.md) → Integrate with AI agents

### Security Researchers
**Check out:** [`src/reveng/javascript/README.md`](src/reveng/javascript/README.md) → Advanced deobfuscation

---

**Still lost?** Open an issue and we'll help you find your way: https://github.com/oimiragieo/reveng-main/issues

**Happy reverse engineering!** 🔓
