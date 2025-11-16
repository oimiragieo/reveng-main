# REVENG Documentation Index

**Complete navigation guide for all REVENG documentation**

Last Updated: November 16, 2025 | Version: 4.0.0

---

## 🎯 Start Here

**New User? Start with these 3 documents:**
1. **[START_HERE.md](START_HERE.md)** - Navigation guide (choose your path)
2. **[QUICK_START.md](QUICK_START.md)** - 2-minute installation and first analysis
3. **[GETTING_STARTED.md](GETTING_STARTED.md)** - Comprehensive getting started guide

---

## 📚 Core Documentation

### Essential Guides
| Document | Purpose | Time to Read |
|----------|---------|--------------|
| [README.md](README.md) | Project overview, features, architecture | 10 min |
| [QUICK_START.md](QUICK_START.md) | Fast installation and first steps | 5 min |
| [GETTING_STARTED.md](GETTING_STARTED.md) | Detailed getting started tutorial | 15 min |
| [INSTALLATION.md](INSTALLATION.md) | Complete installation guide | 20 min |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | All CLI commands and examples | 15 min |

### Feature-Specific Guides
| Document | Purpose |
|----------|---------|
| [docs/mcp/README.md](docs/mcp/README.md) | AI/MCP integration (Claude Desktop) |
| [src/reveng/javascript/README.md](src/reveng/javascript/README.md) | JavaScript deobfuscation (v6.0) |
| [docs/api/API_REFERENCE.md](docs/api/API_REFERENCE.md) | Python API documentation |
| [docs/guides/](docs/guides/) | Feature-specific guides (AI, Ghidra, etc.) |

### Reference Documentation
| Document | Purpose |
|----------|---------|
| [docs/FAQ.md](docs/FAQ.md) | Frequently Asked Questions (40+ questions) |
| [docs/getting-started/troubleshooting.md](docs/getting-started/troubleshooting.md) | Troubleshooting common issues |
| [CHANGELOG.md](CHANGELOG.md) | Version history and changes |
| [SECURITY.md](SECURITY.md) | Security policy and responsible use |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute to REVENG |

---

## 🔧 Setup & Installation

### Quick Path (Recommended)
```
START_HERE.md → QUICK_START.md → First Analysis
     (5 min)          (2 min)        (2 min)
```

### Detailed Path
```
START_HERE.md → INSTALLATION.md → docs/getting-started/ → Advanced Features
     (5 min)         (20 min)            (variable)            (variable)
```

### Installation Documents
1. **[QUICK_START.md](QUICK_START.md)** - One-command installation
2. **[INSTALLATION.md](INSTALLATION.md)** - Detailed setup with all options
3. **[docs/getting-started/installation.md](docs/getting-started/installation.md)** - Extended installation guide
4. **[install-reveng.sh](install-reveng.sh)** - Automated installer script

---

## 💻 User Guides

### By User Type

#### First-Time Users
1. [START_HERE.md](START_HERE.md) - Choose your path
2. [QUICK_START.md](QUICK_START.md) - Get running in 2 minutes
3. [examples/my_first_analysis.py](examples/my_first_analysis.py) - Run your first analysis
4. [docs/FAQ.md](docs/FAQ.md) - Common questions

#### JavaScript Security Researchers
1. [src/reveng/javascript/README.md](src/reveng/javascript/README.md) - JS deobfuscation guide
2. [examples/javascript_deobfuscation_demo.py](examples/javascript_deobfuscation_demo.py) - Demo script
3. `./reveng-js --help` - CLI reference

#### AI/Automation Developers
1. [docs/mcp/README.md](docs/mcp/README.md) - MCP integration guide
2. [docs/api/API_REFERENCE.md](docs/api/API_REFERENCE.md) - Python API
3. [mcp-config.example.json](mcp-config.example.json) - Configuration template
4. [claude.md](claude.md) - Complete AI context (1000+ lines)

#### Security Researchers
1. [docs/guides/advanced-analysis.md](docs/guides/advanced-analysis.md) - Advanced techniques
2. [docs/guides/ghidra-integration.md](docs/guides/ghidra-integration.md) - Ghidra setup
3. [examples/advanced/](examples/advanced/) - Advanced examples
4. [SECURITY.md](SECURITY.md) - Responsible use policy

### By Feature

| Feature | Primary Document | Additional Resources |
|---------|------------------|----------------------|
| **Binary Analysis** | [CLI_REFERENCE.md](CLI_REFERENCE.md) | [docs/api/API_REFERENCE.md](docs/api/API_REFERENCE.md) |
| **JavaScript Deobfuscation** | [src/reveng/javascript/README.md](src/reveng/javascript/README.md) | `./reveng-js --help` |
| **AI Integration** | [docs/mcp/README.md](docs/mcp/README.md) | [docs/guides/ai-enhancements.md](docs/guides/ai-enhancements.md) |
| **Ghidra Setup** | [docs/guides/ghidra-integration.md](docs/guides/ghidra-integration.md) | [INSTALLATION.md](INSTALLATION.md) |
| **Python API** | [docs/api/API_REFERENCE.md](docs/api/API_REFERENCE.md) | [examples/](examples/) |
| **MCP Server** | [docs/mcp/README.md](docs/mcp/README.md) | `./reveng-mcp-server --help` |

---

## 📖 Documentation by Directory

### Root Documentation Files
```
/
├── START_HERE.md                    ← Navigation guide
├── README.md                        ← Project overview
├── QUICK_START.md                   ← Fast setup (2 min)
├── GETTING_STARTED.md               ← Detailed tutorial (15 min)
├── INSTALLATION.md                  ← Complete installation
├── CLI_REFERENCE.md                 ← All CLI commands
├── CHANGELOG.md                     ← Version history
├── SECURITY.md                      ← Security policy
├── CONTRIBUTING.md                  ← Contribution guide
├── CODE_OF_CONDUCT.md               ← Community guidelines
├── LICENSE                          ← MIT License
└── claude.md                        ← Complete AI context (1042 lines)
```

### docs/ Directory
```
docs/
├── README.md                        ← Documentation overview
├── FAQ.md                           ← 40+ common questions
├── index.md                         ← Complete documentation index
├── getting-started/                 ← Setup guides
│   ├── installation.md              ← Extended installation
│   ├── quick-start.md               ← Quick start
│   ├── known-issues.md              ← Known issues
│   └── troubleshooting.md           ← Problem solving
├── mcp/                             ← MCP integration
│   ├── README.md                    ← MCP guide (651 lines)
│   └── claude.md                    ← AI-specific MCP docs
├── api/                             ← API documentation
│   ├── API_REFERENCE.md             ← Python API reference
│   └── AI_API_REFERENCE.md          ← AI API reference
├── guides/                          ← Feature guides
│   ├── ai-enhancements.md           ← AI features
│   ├── ghidra-integration.md        ← Ghidra setup
│   ├── installation.md              ← Installation guide
│   ├── advanced-analysis.md         ← Advanced techniques
│   └── ...                          ← More guides
├── architecture/                    ← System architecture
│   ├── overview.md                  ← Architecture overview
│   ├── pipeline.md                  ← Analysis pipeline
│   └── ghidra-integration.md        ← Ghidra architecture
├── developer-guide/                 ← For contributors
│   ├── DEVELOPER_GUIDE.md           ← Development guide
│   ├── ARCHITECTURE.md              ← Code architecture
│   └── testing.md                   ← Testing guide
└── user-guide/                      ← User documentation
    ├── USER_GUIDE.md                ← Complete user guide
    └── cli-usage.md                 ← CLI usage
```

### examples/ Directory
```
examples/
├── README.md                        ← Examples overview
├── my_first_analysis.py             ← Simplest example (run first!)
├── javascript_deobfuscation_demo.py ← JS deobfuscation demo
├── agent_sdk_demo.py                ← Agent SDK usage
├── basic/                           ← Beginner examples
│   └── 01_simple_analysis.py        ← Simple analysis
├── advanced/                        ← Advanced examples
│   ├── full_recompilation_demo.py   ← Full pipeline
│   ├── gemini_feedback_demo.py      ← AI feedback loop
│   └── v4_0_features_demo.py        ← v4.0 features
├── use-cases/                       ← Real-world scenarios
│   ├── malware-analysis.md          ← Malware analysis
│   ├── legacy-recovery.md           ← Legacy code recovery
│   └── binary-patching.md           ← Binary patching
└── test-samples/                    ← Test files
    └── *.js                         ← JavaScript test samples
```

---

## 🔍 Finding Documentation

### By Task

**I want to install REVENG:**
1. Quick: [QUICK_START.md](QUICK_START.md)
2. Detailed: [INSTALLATION.md](INSTALLATION.md)
3. Troubleshooting: [docs/getting-started/troubleshooting.md](docs/getting-started/troubleshooting.md)

**I want to learn how to use REVENG:**
1. Overview: [README.md](README.md)
2. Tutorial: [GETTING_STARTED.md](GETTING_STARTED.md)
3. Commands: [CLI_REFERENCE.md](CLI_REFERENCE.md)
4. Examples: [examples/my_first_analysis.py](examples/my_first_analysis.py)

**I want to use specific features:**
- JavaScript: [src/reveng/javascript/README.md](src/reveng/javascript/README.md)
- MCP/AI: [docs/mcp/README.md](docs/mcp/README.md)
- Python API: [docs/api/API_REFERENCE.md](docs/api/API_REFERENCE.md)
- Ghidra: [docs/guides/ghidra-integration.md](docs/guides/ghidra-integration.md)

**I have a problem:**
1. FAQ: [docs/FAQ.md](docs/FAQ.md)
2. Troubleshooting: [docs/getting-started/troubleshooting.md](docs/getting-started/troubleshooting.md)
3. Known Issues: [docs/getting-started/known-issues.md](docs/getting-started/known-issues.md)
4. GitHub Issues: https://github.com/oimiragieo/reveng-main/issues

**I want to contribute:**
1. [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
2. [docs/developer-guide/DEVELOPER_GUIDE.md](docs/developer-guide/DEVELOPER_GUIDE.md) - Development setup
3. [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community guidelines

---

## 🚀 Quick Reference

### Essential Commands
```bash
# Installation
./install-reveng.sh

# First analysis
reveng analyze /path/to/binary

# JavaScript deobfuscation
./reveng-js deobfuscate file.js

# MCP server
./reveng-mcp-server

# Get help
reveng --help
./reveng-js --help
./reveng-mcp-server --help
```

### Essential Files for AI Assistants
```
claude.md                            ← Complete project context (1042 lines)
docs/mcp/claude.md                   ← MCP-specific AI docs
src/reveng/claude.md                 ← Source code context
```

**107+ claude.md files** throughout the codebase provide comprehensive AI context for every module.

---

## 📊 Documentation Statistics

| Metric | Count |
|--------|-------|
| **Total Documentation Files** | 303+ |
| **Markdown Files** | 195+ |
| **AI Context Files (claude.md)** | 107+ |
| **Root-Level Docs** | 15 |
| **docs/ Subdirectories** | 15+ |
| **Example Scripts** | 10+ |
| **Lines of Documentation** | ~50,000+ |

---

## 🆘 Still Lost?

### Navigation Helper

1. **Brand new?** → [START_HERE.md](START_HERE.md)
2. **Want to install fast?** → [QUICK_START.md](QUICK_START.md)
3. **Need detailed tutorial?** → [GETTING_STARTED.md](GETTING_STARTED.md)
4. **Have a question?** → [docs/FAQ.md](docs/FAQ.md)
5. **Have a problem?** → [docs/getting-started/troubleshooting.md](docs/getting-started/troubleshooting.md)
6. **Want everything?** → You're reading it! This is the complete index.

### Get Help
- **GitHub Issues**: https://github.com/oimiragieo/reveng-main/issues
- **Discussions**: https://github.com/oimiragieo/reveng-main/discussions
- **Email**: contact@reveng-project.org

---

**Last Updated**: November 16, 2025
**REVENG Version**: 4.0.0 (Production/Stable)
**License**: MIT
