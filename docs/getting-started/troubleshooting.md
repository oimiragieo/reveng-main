# Troubleshooting Guide

Common issues and solutions for the REVENG platform.

## Installation Issues

### Python Version Issues
**Problem**: `Python 3.11+ required`
**Solution**: 
```bash
# Check Python version
python --version

# Install Python 3.11+ if needed
# Windows: Download from python.org
# Linux: sudo apt install python3.11
# macOS: brew install python@3.11
```

### Dependency Installation Failures
**Problem**: `pip install` fails with dependency conflicts
**Solution**:
```bash
# Create virtual environment
python -m venv reveng-env
source reveng-env/bin/activate  # Linux/macOS
# or
reveng-env\Scripts\activate     # Windows

# Install with --upgrade
pip install --upgrade pip
pip install -r requirements.txt
```

### Ghidra Integration Issues
**Problem**: `ghidramcp` import fails
**Solution**:
```bash
# Install Ghidra MCP
pip install ghidramcp

# Set environment variable
export GHIDRA_INSTALL_DIR=/path/to/ghidra  # Linux/macOS
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra   # Windows
```

## Runtime Issues

### Analysis Timeout
**Problem**: Analysis takes too long or times out
**Solution**:
```python
# Increase timeout in configuration
config = {
    'timeout': 7200,  # 2 hours
    'max_file_size_mb': 1000
}
api = REVENGAPI(config)
```

### Memory Issues
**Problem**: `OutOfMemoryError` during analysis
**Solution**:
```python
# Reduce file size limit
config = {
    'max_file_size_mb': 100,  # Reduce from default 500MB
    'timeout': 1800
}
api = REVENGAPI(config)
```

### AI Provider Issues
**Problem**: Enhanced analysis fails with AI errors
**Solution**:
```python
# Use local analysis instead
api = REVENGAPI({'ai_provider': 'none'})
result = api.analyze_binary('/path/to/binary.exe', enhanced=False)
```

## Platform-Specific Issues

### Windows Issues
**Problem**: `'ghidra' is not recognized`
**Solution**:
```cmd
# Add Ghidra to PATH
set PATH=%PATH%;C:\ghidra\ghidra_10.4_PUBLIC

# Or set environment variable
set GHIDRA_INSTALL_DIR=C:\ghidra\ghidra_10.4_PUBLIC
```

### Linux Issues
**Problem**: Permission denied errors
**Solution**:
```bash
# Fix permissions
chmod +x /path/to/ghidra/ghidraRun

# Install required system packages
sudo apt install openjdk-11-jdk gcc g++ make
```

### macOS Issues
**Problem**: Java not found
**Solution**:
```bash
# Install Java
brew install openjdk@11

# Set JAVA_HOME
export JAVA_HOME=/opt/homebrew/opt/openjdk@11
```

## Web Interface Issues

### Port Already in Use
**Problem**: `Address already in use`
**Solution**:
```bash
# Use different port
reveng serve --port 3001

# Or kill existing process
lsof -ti:3000 | xargs kill -9  # Linux/macOS
netstat -ano | findstr :3000   # Windows
```

### Web Interface Not Loading
**Problem**: Browser shows connection refused
**Solution**:
```bash
# Check if service is running
reveng serve --host 0.0.0.0 --port 3000

# Check firewall settings
# Windows: Windows Defender Firewall
# Linux: ufw or iptables
# macOS: System Preferences > Security & Privacy
```

## Analysis Issues

### Unsupported Binary Format
**Problem**: `Unsupported binary format`
**Solution**:
```python
# Check binary type
from reveng.api import REVENGAPI
api = REVENGAPI()
result = api.analyze_binary('/path/to/binary')
print(result['binary']['type'])

# Use appropriate analyzer
if result['binary']['type'] == 'PE32':
    # Use Windows-specific analysis
    pass
```

### Low Confidence Results
**Problem**: Analysis results have low confidence
**Solution**:
```python
# Enable enhanced analysis
result = api.analyze_binary('/path/to/binary', enhanced=True)

# Check ML insights
print(result['ml_insights'])

# Use specific modules
result = api.analyze_binary('/path/to/binary', modules=['malware_detection'])
```

## Performance Issues

### Slow Analysis
**Problem**: Analysis takes too long
**Solution**:
```python
# Use specific modules only
result = api.analyze_binary('/path/to/binary', modules=['basic_analysis'])

# Disable enhanced features
result = api.analyze_binary('/path/to/binary', enhanced=False)

# Use smaller file size limit
config = {'max_file_size_mb': 50}
api = REVENGAPI(config)
```

### High Memory Usage
**Problem**: System runs out of memory
**Solution**:
```python
# Process in chunks
config = {
    'max_file_size_mb': 100,
    'chunk_size_mb': 10
}
api = REVENGAPI(config)
```

## Error Messages

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `File not found` | Invalid path | Check file path and permissions |
| `File too large` | Exceeds size limit | Increase `max_file_size_mb` or reduce file size |
| `Timeout exceeded` | Analysis too slow | Increase `timeout` or use smaller file |
| `Dependency missing` | Required tool not installed | Install missing dependency |
| `Permission denied` | Insufficient permissions | Check file permissions and user rights |

### Debug Mode
Enable debug logging for detailed error information:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Run analysis with debug output
result = api.analyze_binary('/path/to/binary')
```

## Getting Help

### Log Files
Check log files for detailed error information:
- `reveng_analyzer.log` - Main analysis log
- `~/.reveng/logs/` - User-specific logs
- `/var/log/reveng/` - System logs (Linux)

### Community Support
- [GitHub Issues](https://github.com/oimiragieo/reveng-main/issues) - Bug reports
- [GitHub Discussions](https://github.com/oimiragieo/reveng-main/discussions) - Questions and help
- [Security Issues](SECURITY.md) - Security-related problems

### Professional Support
For enterprise support and custom solutions:
- Contact: support@reveng-project.org
- Documentation: [Enterprise Guide](deployment/production.md)
