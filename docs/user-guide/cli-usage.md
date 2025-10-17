# CLI Usage Guide

Complete command-line interface documentation for REVENG.

## Installation

```bash
# Install from PyPI
pip install reveng-toolkit

# Or install from source
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
pip install -e .
```

## Basic Commands

### Analyze Binary
```bash
# Basic analysis
reveng analyze malware.exe

# Enhanced AI analysis
reveng analyze --enhanced suspicious.jar

# Specify output directory
reveng analyze --output ./results malware.exe

# Use specific modules
reveng analyze --modules malware_detection,vulnerability_analysis target.exe
```

### Web Interface
```bash
# Start web interface
reveng serve

# Custom host and port
reveng serve --host 0.0.0.0 --port 3000

# With authentication
reveng serve --auth --username admin --password secret
```

### Configuration
```bash
# Show current configuration
reveng config show

# Set configuration
reveng config set timeout 7200
reveng config set max_file_size_mb 1000

# Reset to defaults
reveng config reset
```

## Command Reference

### `reveng analyze`
Analyze a binary file.

**Syntax:**
```bash
reveng analyze [OPTIONS] BINARY_PATH
```

**Options:**
- `--enhanced`: Enable ML-enhanced analysis
- `--output DIR`: Output directory for results
- `--format FORMAT`: Output format (json, xml, yaml)
- `--modules MODULES`: Comma-separated list of modules to run
- `--timeout SECONDS`: Analysis timeout in seconds
- `--max-size MB`: Maximum file size in MB
- `--verbose`: Verbose output
- `--quiet`: Quiet mode

**Examples:**
```bash
# Basic analysis
reveng analyze malware.exe

# Enhanced analysis with custom output
reveng analyze --enhanced --output ./results --format json suspicious.exe

# Specific modules only
reveng analyze --modules malware_detection,string_analysis target.exe

# Large file with extended timeout
reveng analyze --timeout 7200 --max-size 2000 large_binary.exe
```

### `reveng serve`
Start the web interface.

**Syntax:**
```bash
reveng serve [OPTIONS]
```

**Options:**
- `--host HOST`: Host to bind to (default: localhost)
- `--port PORT`: Port to bind to (default: 3000)
- `--auth`: Enable authentication
- `--username USER`: Username for authentication
- `--password PASS`: Password for authentication
- `--workers N`: Number of worker processes

**Examples:**
```bash
# Basic web interface
reveng serve

# Public access
reveng serve --host 0.0.0.0 --port 8080

# With authentication
reveng serve --auth --username admin --password secret123
```

### `reveng config`
Manage configuration settings.

**Syntax:**
```bash
reveng config [COMMAND] [OPTIONS]
```

**Commands:**
- `show`: Show current configuration
- `set KEY VALUE`: Set configuration value
- `get KEY`: Get configuration value
- `reset`: Reset to defaults
- `validate`: Validate configuration

**Examples:**
```bash
# Show all settings
reveng config show

# Set timeout
reveng config set timeout 3600

# Set AI provider
reveng config set ai_provider claude

# Validate configuration
reveng config validate
```

### `reveng plugins`
Manage plugins.

**Syntax:**
```bash
reveng plugins [COMMAND] [OPTIONS]
```

**Commands:**
- `list`: List installed plugins
- `install PLUGIN`: Install a plugin
- `uninstall PLUGIN`: Uninstall a plugin
- `enable PLUGIN`: Enable a plugin
- `disable PLUGIN`: Disable a plugin

**Examples:**
```bash
# List plugins
reveng plugins list

# Install custom plugin
reveng plugins install reveng-plugin-custom

# Enable specific plugin
reveng plugins enable malware-detector
```

## Configuration Options

### Analysis Settings
- `timeout`: Analysis timeout in seconds (default: 3600)
- `max_file_size_mb`: Maximum file size in MB (default: 500)
- `output_directory`: Default output directory (default: ./analysis_output)
- `ai_provider`: AI provider (ollama, claude, openai, none)

### AI Settings
- `ai_model`: AI model to use
- `ai_timeout`: AI request timeout
- `ai_retries`: Number of retries for AI requests

### Security Settings
- `enable_sandbox`: Enable sandboxing (default: true)
- `max_memory_mb`: Maximum memory usage in MB
- `allowed_extensions`: Allowed file extensions

### Output Settings
- `default_format`: Default output format (json, xml, yaml)
- `include_metadata`: Include metadata in output
- `compress_output`: Compress output files

## Environment Variables

Set these environment variables for configuration:

```bash
# AI Provider Settings
export ANTHROPIC_API_KEY="your-claude-key"
export OPENAI_API_KEY="your-openai-key"
export OLLAMA_HOST="http://localhost:11434"

# Ghidra Integration
export GHIDRA_INSTALL_DIR="/path/to/ghidra"

# Analysis Settings
export REVENG_TIMEOUT="3600"
export REVENG_MAX_SIZE="500"
export REVENG_OUTPUT_DIR="./results"

# Security Settings
export REVENG_SANDBOX="true"
export REVENG_MAX_MEMORY="2048"
```

## Output Formats

### JSON Output
```bash
reveng analyze --format json malware.exe
```
Produces structured JSON with analysis results.

### XML Output
```bash
reveng analyze --format xml malware.exe
```
Produces XML format for integration with other tools.

### YAML Output
```bash
reveng analyze --format yaml malware.exe
```
Produces human-readable YAML format.

## Batch Processing

### Process Multiple Files
```bash
# Process all files in directory
for file in *.exe; do
    reveng analyze "$file" --output "./results/$file"
done

# Using find command
find ./binaries -name "*.exe" -exec reveng analyze {} --output ./results \;
```

### Script Integration
```bash
#!/bin/bash
# Batch analysis script

INPUT_DIR="./malware_samples"
OUTPUT_DIR="./analysis_results"

mkdir -p "$OUTPUT_DIR"

for file in "$INPUT_DIR"/*; do
    if [ -f "$file" ]; then
        echo "Analyzing: $file"
        reveng analyze "$file" --output "$OUTPUT_DIR" --format json
    fi
done
```

## Troubleshooting

### Common Issues

**Command not found:**
```bash
# Check installation
pip show reveng-toolkit

# Reinstall if needed
pip install --upgrade reveng-toolkit
```

**Permission denied:**
```bash
# Check file permissions
ls -la malware.exe

# Fix permissions if needed
chmod +r malware.exe
```

**Analysis timeout:**
```bash
# Increase timeout
reveng analyze --timeout 7200 large_file.exe
```

### Debug Mode
```bash
# Enable verbose output
reveng analyze --verbose malware.exe

# Check logs
tail -f ~/.reveng/logs/reveng.log
```

## Integration Examples

### Python Script
```python
import subprocess
import json

def analyze_binary(binary_path):
    cmd = ['reveng', 'analyze', '--format', 'json', binary_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)

# Usage
result = analyze_binary('malware.exe')
print(f"Threat level: {result['threat_assessment']['threat_level']}")
```

### Shell Script
```bash
#!/bin/bash
# Automated analysis script

BINARY="$1"
OUTPUT_DIR="./results"

if [ -z "$BINARY" ]; then
    echo "Usage: $0 <binary_file>"
    exit 1
fi

echo "Analyzing: $BINARY"
reveng analyze "$BINARY" --output "$OUTPUT_DIR" --format json

if [ $? -eq 0 ]; then
    echo "Analysis completed successfully"
else
    echo "Analysis failed"
    exit 1
fi
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Analyze Binary
  run: |
    reveng analyze malware.exe --output ./results --format json
    
- name: Upload Results
  uses: actions/upload-artifact@v3
  with:
    name: analysis-results
    path: ./results/
```
