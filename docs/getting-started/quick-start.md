# Quick Start Guide

Get REVENG running in 3 commands and analyze your first binary in under 5 minutes.

## 🚀 Installation

### Option 1: PyPI (Recommended)
```bash
pip install reveng-toolkit
```

### Option 2: Docker
```bash
# CLI version
docker pull reveng/cli:latest

# Web interface
docker pull reveng/web:latest
```

### Option 3: From Source
```bash
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
pip install -e .
```

## ⚡ First Analysis

### CLI Analysis
```bash
# Basic analysis
reveng analyze suspicious.exe

# Enhanced AI analysis
reveng analyze --enhanced malware.jar

# Web interface
reveng serve --port 3000
```

### Web Interface
```bash
# Start web server
reveng serve

# Open browser to http://localhost:3000
# - Upload binary files
# - Real-time analysis progress
# - Interactive visualizations
# - Team collaboration
```

## 🎯 Choose Your Workflow

### CLI Users
Perfect for:
- Automated analysis scripts
- CI/CD pipelines
- Batch processing
- Server environments

```bash
# Analyze single file
reveng analyze target.exe

# Batch analysis
for file in *.exe; do
    reveng analyze "$file"
done

# Enhanced analysis with AI
reveng analyze --enhanced --ai-provider ollama malware.exe
```

### Web Users
Perfect for:
- Interactive analysis
- Team collaboration
- Visual exploration
- Project management

```bash
# Start web interface
reveng serve --host 0.0.0.0 --port 3000

# Access at http://localhost:3000
# Features:
# - Drag & drop file upload
# - Real-time progress tracking
# - Interactive result visualization
# - Team project sharing
```

## 🔧 Configuration

### Basic Configuration
```yaml
# ~/.reveng/config.yaml
ai:
  provider: ollama  # ollama, claude, openai
  model: llama2
  enabled: true

analysis:
  enhanced_features: true
  timeout: 300
  max_memory: 2048

output:
  format: json
  directory: ./analysis_results
```

### Environment Variables
```bash
# AI Configuration
export REVENG_AI_PROVIDER=ollama
export REVENG_AI_MODEL=llama2
export REVENG_AI_API_KEY=your_key_here

# Analysis Settings
export REVENG_ENHANCED_ANALYSIS=true
export REVENG_TIMEOUT=300
export REVENG_MAX_MEMORY=2048
```

## 📊 Supported File Types

| Language | Extensions | Analysis | Reconstruction |
|----------|------------|----------|----------------|
| **Java** | `.jar`, `.war`, `.ear`, `.class` | ✅ | ✅ |
| **C#** | `.dll`, `.exe` (.NET) | ✅ | ✅ |
| **Python** | `.pyc`, `.pyo` | ✅ | ✅ |
| **Native** | `.exe`, `.dll`, `.so`, `.dylib` | ✅ | ✅ |

## 🎨 Web Interface Features

### Real-time Analysis
- Live progress tracking
- Interactive visualizations
- Real-time collaboration
- Project management

### Team Features
- Shared projects
- Role-based access
- Audit trails
- Export capabilities

### Visualization
- Control flow graphs
- Function call trees
- Data flow analysis
- Security findings

## 🚨 Troubleshooting

### Common Issues

**Installation Problems**
```bash
# Update pip
pip install --upgrade pip

# Install with dependencies
pip install reveng-toolkit[all]

# Check Python version
python --version  # Should be 3.11+
```

**Analysis Failures**
```bash
# Check file permissions
ls -la target.exe

# Verify file type
file target.exe

# Run with verbose output
reveng analyze --verbose target.exe
```

**Web Interface Issues**
```bash
# Check port availability
netstat -an | grep 3000

# Use different port
reveng serve --port 3001

# Check firewall settings
```

### Getting Help

- 📖 [Documentation](https://docs.reveng-toolkit.org)
- 💬 [Discussions](https://github.com/oimiragieo/reveng-main/discussions)
- 🐛 [Issue Tracker](https://github.com/oimiragieo/reveng-main/issues)
- 📧 [Email Support](mailto:support@reveng-project.org)

## 🎯 Next Steps

Now that you have REVENG running:

1. **Try the Tutorial**: [First Analysis](first-analysis.md)
2. **Explore Features**: [User Guide](../user-guide/)
3. **Configure AI**: [AI Features](../user-guide/ai-features.md)
4. **Deploy Web Interface**: [Deployment](../deployment/)

## 🔗 Related Guides

- [Installation Guide](installation.md) - Detailed setup instructions
- [First Analysis Tutorial](first-analysis.md) - Step-by-step walkthrough
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [CLI Usage](../user-guide/cli-usage.md) - Command-line interface
- [Web Interface](../user-guide/web-interface.md) - Web UI guide
