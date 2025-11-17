# REVENG CLI Command Reference

Complete reference for all REVENG command-line interface commands.

**Version:** 4.0.0

---

## Quick Reference

```bash
# Get version
reveng --version

# Core Analysis
reveng analyze <binary>          # Comprehensive binary analysis
reveng triage <binary>            # Quick 30-second threat assessment
reveng ai <binary>                # AI-powered analysis

# Interactive
reveng serve                      # Start web interface
reveng ask "question" <binary>    # Natural language query

# Threat Intelligence
reveng vt-lookup <binary>         # VirusTotal lookup
reveng vt-submit <binary>         # Submit to VirusTotal

# YARA Operations
reveng generate-yara <binary>     # Generate YARA rules
reveng scan-yara <rules> <target> # Scan with YARA rules

# Binary Comparison
reveng diff <binary1> <binary2>   # Binary diffing
reveng patch-analysis <old> <new> # Security patch analysis

# Unpacking & Code Enhancement
reveng detect-packer <binary>     # Detect packers
reveng unpack <binary>            # Unpack binary
reveng enhance-code <source>      # AI code enhancement
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

## Command: `vt-submit`

Submit file to VirusTotal for analysis.

### Syntax

```bash
reveng vt-submit <binary_path> [OPTIONS]
```

### Description

Upload binary to VirusTotal and optionally wait for analysis results. Useful when file hasn't been analyzed before.

### Options

- `--api-key <key>` - VirusTotal API key (or set VT_API_KEY environment variable)
- `--wait` - Wait for analysis to complete before returning

### Examples

```bash
# Submit file
reveng vt-submit unknown.exe

# Submit and wait for results
reveng vt-submit unknown.exe --wait

# Use custom API key
reveng vt-submit unknown.exe --api-key YOUR_KEY
```

### Requirements

- VirusTotal API key: `VT_API_KEY`
- Internet connection

---

## Command: `unpack`

Unpack packed/compressed binary.

### Syntax

```bash
reveng unpack <binary_path> [OPTIONS]
```

### Description

Attempt to unpack or decompress a packed binary using various unpacking methods. Automatically detects packer type and applies appropriate unpacking technique.

### Options

- `--output <path>` - Path for unpacked binary (default: auto-generated)
- `--method <type>` - Unpacking method:
  - `auto` - Automatic detection (default)
  - `specialized` - Use specialized unpacker for detected packer
  - `generic` - Use generic unpacking techniques

### Examples

```bash
# Auto-detect and unpack
reveng unpack packed.exe

# Specify output path
reveng unpack packed.exe --output unpacked.exe

# Use generic unpacking method
reveng unpack packed.exe --method generic
```

### Supported Packers

Common packers that can be detected and unpacked:
- UPX
- ASPack
- PECompact
- Themida (partial)
- VMProtect (partial)
- And many more...

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

## Command: `generate-yara`

Generate YARA rules from binaries.

### Syntax

```bash
reveng generate-yara [OPTIONS] <binary_path>
```

### Description

Automatically generates YARA rules for malware detection and classification based on binary analysis. Extracts unique patterns, strings, and behavioral characteristics.

### Options

- `--output <path>` - Output YARA rule file (default: stdout)
- `--name <rule_name>` - Custom rule name (default: auto-generated)
- `--strict` - Generate strict rules with high specificity
- `--loose` - Generate loose rules for family detection

### Examples

```bash
# Generate YARA rule for malware
reveng generate-yara malware.exe -o malware.yar

# Generate strict rule with custom name
reveng generate-yara --strict --name "Trojan_Custom" suspicious.dll

# Generate family-based rule
reveng generate-yara --loose ransomware.exe
```

### Requirements

- Binary analysis completed
- Write access to output directory

---

## Command: `scan-yara`

Scan binaries using YARA rules.

### Syntax

```bash
reveng scan-yara [OPTIONS] <rule_path> <target>
```

### Description

Scan single binary or directory of binaries using YARA rules. Supports both custom and standard YARA rule sets.

### Options

- `--recursive` - Scan directories recursively
- `--threads <n>` - Number of scanning threads (default: 4)
- `--output <path>` - Save results to JSON file
- `--match-only` - Show only matching files

### Examples

```bash
# Scan single file
reveng scan-yara rules.yar suspicious.exe

# Scan directory recursively
reveng scan-yara --recursive malware_rules/ /samples/

# Fast scan with 8 threads
reveng scan-yara --threads 8 --match-only rules.yar /binaries/
```

### Requirements

- YARA rule file in valid format
- Read access to target files

---

## Command: `diff`

Binary diffing and comparison.

### Syntax

```bash
reveng diff [OPTIONS] <binary1> <binary2>
```

### Description

Performs semantic binary diffing to identify changes between two versions of a binary. Uses advanced algorithms including Hungarian algorithm for function matching.

Useful for:
- Patch analysis and security updates
- Version comparison
- Malware variant analysis
- Code evolution tracking

### Options

- `--algorithm <type>` - Diffing algorithm: `semantic`, `structural`, `byte` (default: semantic)
- `--output <path>` - Save diff results to file
- `--format <format>` - Output format: `json`, `html`, `text` (default: text)
- `--similarity <threshold>` - Minimum similarity threshold (0.0-1.0, default: 0.7)

### Examples

```bash
# Basic semantic diff
reveng diff old_version.exe new_version.exe

# Detailed HTML report
reveng diff --format html --output report.html v1.dll v2.dll

# Find similar functions with custom threshold
reveng diff --similarity 0.8 original.bin patched.bin
```

### Requirements

- Two binary files in compatible formats
- Sufficient memory for analysis

---

## Command: `patch-analysis`

Security patch analysis and vulnerability detection.

### Syntax

```bash
reveng patch-analysis [OPTIONS] <original_binary> <patched_binary>
```

### Description

Analyzes security patches by comparing original and patched binaries to identify:
- Fixed vulnerabilities
- Security improvements
- Changed functions
- Attack surface reduction

Generates detailed security assessment reports.

### Options

- `--output <path>` - Save analysis report
- `--format <format>` - Report format: `json`, `markdown`, `html`
- `--cve <id>` - Associate with CVE identifier
- `--severity` - Include severity assessment

### Examples

```bash
# Analyze security patch
reveng patch-analysis vulnerable.dll patched.dll

# Full report with CVE tracking
reveng patch-analysis --cve CVE-2024-1234 --severity old.exe new.exe

# JSON output for automation
reveng patch-analysis --format json --output patch_report.json app_v1.bin app_v2.bin
```

### Requirements

- Two versions of same binary (original + patched)
- Analysis permissions

---

## Command: `detect-packer`

Detect binary packers and obfuscators.

### Syntax

```bash
reveng detect-packer [OPTIONS] <binary_path>
```

### Description

Identifies packers, crypters, and obfuscators used to protect or hide binary code. Detects:
- UPX, ASPack, PECompact, Themida, VMProtect
- Custom packers
- Obfuscation layers
- Anti-debugging techniques

### Options

- `--verbose` - Show detailed detection information
- `--signatures <path>` - Custom signature database
- `--output <path>` - Save detection results

### Examples

```bash
# Detect packer
reveng detect-packer packed_malware.exe

# Verbose detection with custom signatures
reveng detect-packer --verbose --signatures custom_sigs.db binary.exe

# Save results for batch processing
reveng detect-packer --output results.json suspicious.dll
```

### Output

Returns packer name, confidence level, and unpacking recommendations.

---

## Command: `enhance-code`

AI-powered code enhancement and optimization.

### Syntax

```bash
reveng enhance-code [OPTIONS] <source_file>
```

### Description

Uses AI to enhance decompiled or disassembled code by:
- Adding meaningful variable names
- Inferring types
- Adding comments and documentation
- Improving code structure
- Suggesting optimizations

### Options

- `--output <path>` - Enhanced code output file
- `--model <name>` - AI model: `gemini`, `claude`, `gpt4` (default: gemini)
- `--language <lang>` - Source language: `c`, `cpp`, `java`, `csharp`
- `--aggressive` - Apply aggressive transformations

### Examples

```bash
# Enhance decompiled C code
reveng enhance-code decompiled.c -o enhanced.c

# Use Claude for C++ code
reveng enhance-code --model claude --language cpp source.cpp

# Aggressive enhancement
reveng enhance-code --aggressive messy_code.c
```

### Requirements

- AI API key (GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY)
- Valid source code file

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
