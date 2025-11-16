# REVENG CLI Command Reference

Complete reference for all REVENG command-line interface commands.

**Version:** 4.0.0

---

## Quick Reference

```bash
# Get version
reveng --version

# Analyze a binary
reveng analyze <binary>

# Start web interface
reveng serve

# Natural language query
reveng ask "What does this binary do?" <binary>

# AI-powered analysis
reveng ai <binary>

# Quick triage
reveng triage <binary>

# VirusTotal lookup
reveng vt-lookup <binary>
```

---

## Command: `analyze`

Comprehensive binary analysis.

### Syntax

```bash
reveng analyze [OPTIONS] <binary_path>
```

### Description

Runs comprehensive binary analysis on the specified file, including:
- Binary format detection
- Static code analysis
- Security vulnerability scanning
- Threat intelligence lookup (if configured)
- Optional: AI-enhanced analysis
- Optional: Ghidra decompilation

### Options

- `--enhanced` - Enable AI-enhanced analysis (requires API keys)
- `--output <path>` - Output results to file
- `--format <format>` - Output format: `json`, `markdown`, `html`
- `--timeout <seconds>` - Analysis timeout (default: 300)

### Examples

```bash
# Basic analysis
reveng analyze suspicious.exe

# Enhanced analysis with AI
reveng analyze --enhanced malware.jar

# Save results to JSON
reveng analyze --output results.json --format json binary.dll
```

### Requirements

- **Core:** Python 3.9+, REVENG installed
- **Enhanced:** API keys (GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY)
- **Ghidra:** Ghidra server running for advanced decompilation

---

## Command: `serve`

Start the REVENG web interface.

### Syntax

```bash
reveng serve [OPTIONS]
```

### Description

Launches the web interface for interactive binary analysis, project management, and team collaboration.

### Options

- `--host <host>` - Bind address (default: localhost)
- `--port <port>` - Port number (default: 3000)
- `--reload` - Enable auto-reload for development

### Examples

```bash
# Start on default port
reveng serve

# Custom host and port
reveng serve --host 0.0.0.0 --port 8080

# Development mode with reload
reveng serve --reload
```

### Access

Open browser to: `http://localhost:3000`

---

## Command: `ask`

Natural language interface for binary analysis.

### Syntax

```bash
reveng ask [OPTIONS] "<question>" [binary_path]
```

### Description

Use natural language to ask questions about binary functionality, behavior, and security.

Powered by AI models (Gemini, Claude, GPT-4).

### Options

- `--analysis-results <path>` - Use previous analysis results
- `--conversational` - Enable conversational mode for follow-up questions

### Examples

```bash
# Ask about binary behavior
reveng ask "What does this binary do?" malware.exe

# Security-focused question
reveng ask "Does this binary have any vulnerabilities?" app.dll

# Using cached analysis
reveng ask "What network connections does it make?" --analysis-results results.json
```

### Requirements

- API key for AI provider (GEMINI_API_KEY recommended)
- Binary file or previous analysis results

---

## Command: `ai`

Interactive AI assistant for comprehensive analysis.

### Syntax

```bash
reveng ai [OPTIONS] <binary_path>
```

### Description

Start an interactive AI assistant session that guides you through comprehensive binary analysis with intelligent recommendations.

### Options

- `--analysis-type <type>` - Analysis type: `comprehensive`, `security`, `triage`, `custom`
- `--goals <goals>` - Analysis goals (space-separated)
- `--interactive` - Enable interactive mode for follow-up questions

### Examples

```bash
# Comprehensive analysis
reveng ai malware.exe

# Security-focused analysis
reveng ai --analysis-type security vulnerable.dll

# Custom analysis with specific goals
reveng ai --goals understand_functionality find_vulnerabilities --interactive binary.exe
```

### Analysis Types

- **comprehensive** - Full analysis (default)
- **security** - Focus on vulnerabilities and exploits
- **triage** - Quick assessment for incident response
- **custom** - User-defined goals

---

## Command: `triage`

Rapid threat assessment for incident response.

### Syntax

```bash
reveng triage [OPTIONS] <binary_path>
```

### Description

Performs instant threat assessment in under 30 seconds, ideal for incident response and malware triage.

### Options

- `--bulk <files>` - Triage multiple files in batch
- `--format <format>` - Output format: `text`, `json`, `markdown`

### Examples

```bash
# Quick triage
reveng triage suspicious.exe

# Batch triage
reveng triage --bulk *.exe

# JSON output for automation
reveng triage --format json malware.dll
```

### Output

```
Threat Level: HIGH
Malware Family: TrojanDownloader
IOCs: [IPs, domains, file hashes]
Behavioral Indicators: [...]
Recommended Action: Quarantine and analyze
```

---

## Command: `vt-lookup`

VirusTotal threat intelligence lookup.

### Syntax

```bash
reveng vt-lookup <binary_path|hash>
```

### Description

Enriches analysis with VirusTotal threat intelligence data.

### Requirements

- VirusTotal API key: `VIRUSTOTAL_API_KEY`
- Configuration: `~/.reveng/config.yaml`

### Examples

```bash
# Lookup by file
reveng vt-lookup malware.exe

# Lookup by hash
reveng vt-lookup a1b2c3d4e5f6...
```

---

## Global Options

Available for all commands:

- `--version`, `-v` - Show version and exit
- `--help`, `-h` - Show help message
- `--verbose` - Enable verbose output
- `--quiet` - Suppress non-essential output
- `--config <path>` - Use custom configuration file

---

## Environment Variables

Configure REVENG behavior via environment variables:

### API Keys

```bash
# Google Gemini (recommended)
export GEMINI_API_KEY="your-key-here"

# OpenAI GPT-4
export OPENAI_API_KEY="sk-your-key-here"

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# VirusTotal
export VIRUSTOTAL_API_KEY="your-vt-key"
```

### Configuration

```bash
# AI Provider
export REVENG_AI_PROVIDER="gemini"  # gemini, openai, anthropic, ollama

# Analysis Settings
export REVENG_ENHANCED_ANALYSIS="true"
export REVENG_TIMEOUT="300"
export REVENG_MAX_MEMORY="2048"

# Ghidra Server
export GHIDRA_SERVER_URL="http://localhost:13370"
```

---

## Configuration File

Location: `~/.reveng/config.yaml`

```yaml
# AI Configuration
ai:
  provider: gemini  # gemini, openai, anthropic, ollama
  model: gemini-pro
  enabled: true
  api_keys:
    gemini: "your-key"
    openai: "your-key"
    anthropic: "your-key"

# Analysis Settings
analysis:
  enhanced_features: true
  timeout: 300
  max_memory: 2048
  parallel_workers: 4

# Ghidra Integration
ghidra:
  enabled: true
  server_url: "http://localhost:13370"
  timeout: 300

# VirusTotal
virustotal:
  enabled: true
  api_key: "your-vt-key"

# Output Settings
output:
  format: json
  directory: ./analysis_results
  verbose: false
```

---

## Return Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | File not found |
| 3 | Invalid arguments |
| 4 | Analysis failed |
| 5 | Timeout |
| 10 | Configuration error |
| 11 | Missing dependencies |
| 12 | API error |

---

## Examples by Use Case

### Security Research

```bash
# Comprehensive malware analysis
reveng analyze --enhanced --output report.json malware.exe

# Find vulnerabilities
reveng ask "What vulnerabilities exist in this binary?" app.dll

# Generate exploit PoC
reveng ai --analysis-type security --goals generate_exploits vuln.exe
```

### Incident Response

```bash
# Quick triage
reveng triage suspicious.exe

# Batch triage
reveng triage --bulk *.dll --format json

# VirusTotal check
reveng vt-lookup suspicious.exe
```

### Reverse Engineering

```bash
# Understand functionality
reveng ask "What is the main purpose of this binary?" program.exe

# Interactive exploration
reveng ai --interactive binary.exe

# Web interface for detailed analysis
reveng serve --port 3000
```

### Automation

```bash
# Batch analysis with JSON output
for file in samples/*.exe; do
    reveng analyze --format json --output "results/${file}.json" "$file"
done

# Integration with scripts
reveng triage --format json malware.exe | jq '.threat_level'
```

---

## JavaScript Deobfuscation

REVENG includes a separate tool for JavaScript deobfuscation:

```bash
# Basic deobfuscation
./reveng-js deobfuscate obfuscated.js -o clean.js

# With ML variable renaming
./reveng-js deobfuscate --ml obfuscated.js -o clean.js

# Detect malware
./reveng-js analyze suspicious.js

# Batch processing
./reveng-js deobfuscate --batch *.js
```

See: `src/reveng/javascript/README.md` for full documentation.

---

## MCP Server (AI Integration)

Start the Model Context Protocol server for AI agent integration:

```bash
# stdio mode (for Claude Desktop)
./reveng-mcp-server

# HTTP mode (for network access)
./reveng-mcp-server --transport http --port 8080

# With authentication
./reveng-mcp-server --transport http --port 8080 --auth-token <token>
```

See: `docs/mcp/README.md` for full MCP documentation.

---

## Troubleshooting

### Command Not Found

```bash
# Verify installation
reveng --version

# Reinstall if needed
pip install -e .
```

### Analysis Fails

```bash
# Check file permissions
ls -la binary.exe

# Verify file type
file binary.exe

# Run with verbose output
reveng analyze --verbose binary.exe
```

### Ghidra Not Working

```bash
# Start Ghidra server
cd external/ghidra-server
python ghidra_http_server.py

# Verify it's running
curl http://localhost:13370/health
```

### API Errors

```bash
# Check API key is set
echo $GEMINI_API_KEY

# Verify configuration
cat ~/.reveng/config.yaml

# Test with simple query
reveng ask "test" --verbose
```

---

## Getting Help

- **Documentation**: `docs/`
- **Issues**: https://github.com/oimiragieo/reveng-main/issues
- **Discussions**: https://github.com/oimiragieo/reveng-main/discussions
- **Email**: contact@reveng-project.org

---

## Version History

- **4.0.0** - Enterprise AI Tool Suite with MCP integration
- **3.2.0** - Enhanced Ghidra integration
- **3.0.0** - Multi-language support
- **2.2.0** - ML-assisted triage
- **2.0.0** - AI-powered analysis
- **1.0.0** - Initial release

---

*Last updated: November 16, 2025*
