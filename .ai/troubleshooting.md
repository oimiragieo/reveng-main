# REVENG Troubleshooting Guide

This guide helps you diagnose and fix common issues when working with REVENG.

## 🔍 Common Issues

### 1. Tool Not Found Errors

#### Problem: "Tool not found" or "No module named"
```bash
# Error: python: can't open file 'tools/tool_name.py': [Errno 2] No such file or directory
```

#### Solutions:
```bash
# Check if tool exists in new categorized structure
ls tools/category/tool_name.py

# Check Python path
python -c "import sys; print(sys.path)"

# Check current directory
pwd
```

#### Root Cause:
- Tools moved to categorized subdirectories
- Import paths not updated
- Working directory incorrect

### 2. Import Errors

#### Problem: ImportError or ModuleNotFoundError
```python
# Error: ModuleNotFoundError: No module named 'tools.tool_name'
```

#### Solutions:
```bash
# Install missing dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Check imports
python -c "import tools.category.tool_name"

# Update import paths in code
# Old: from tools.tool_name import function
# New: from tools.category.tool_name import function
```

#### Root Cause:
- Missing dependencies
- Import paths not updated after reorganization
- Python path issues

### 3. Permission Errors

#### Problem: Permission denied or access errors
```bash
# Error: PermissionError: [Errno 13] Permission denied
```

#### Solutions:
```bash
# Check file permissions
ls -la tools/category/tool_name.py

# Make executable
chmod +x tools/category/tool_name.py

# Check directory permissions
ls -la tools/category/

# Run with appropriate permissions
sudo python tools/category/tool_name.py
```

#### Root Cause:
- File not executable
- Insufficient permissions
- Directory access issues

### 4. Memory Issues

#### Problem: Out of memory or memory errors
```python
# Error: MemoryError: Unable to allocate array
```

#### Solutions:
```bash
# Use smaller files for testing
# Increase system memory
# Use streaming for large files

# Check memory usage
python -c "import psutil; print(f'Memory: {psutil.virtual_memory().percent}%')"

# Monitor memory during analysis
python -m memory_profiler tools/category/tool_name.py
```

#### Root Cause:
- Large binary files
- Inefficient memory usage
- System memory limitations

### 5. Analysis Failures

#### Problem: Analysis steps failing or timing out
```bash
# Error: Analysis failed or timed out
```

#### Solutions:
```bash
# Check logs
tail -f *.log

# Verify toolchain
python tools/binary/check_toolchain.py --fix

# Test individual tools
python tools/category/tool_name.py --help
python tools/category/tool_name.py test_input

# Increase timeout values
# Edit reveng_analyzer.py timeout settings
```

#### Root Cause:
- Missing dependencies
- Toolchain issues
- Timeout too short
- Input file issues

## 🛠️ Debugging Tools

### 1. Log Analysis
```bash
# Check main analyzer log
tail -f reveng_analyzer.log

# Check specific tool logs
tail -f ai_recompiler_converter.log
tail -f optimal_binary_analysis.log

# Search for errors
grep -i error *.log
grep -i exception *.log
```

### 2. Toolchain Verification
```bash
# Check toolchain status
python tools/binary/check_toolchain.py

# Fix toolchain issues
python tools/binary/check_toolchain.py --fix

# Verify specific tools
python tools/binary/check_toolchain.py --check-ghidra
python tools/binary/check_toolchain.py --check-ollama
```

### 3. Dependency Checking
```bash
# Check Python dependencies
pip list

# Check for missing packages
pip check

# Verify imports
python -c "import lief, keystone, capstone, requests"
```

### 4. System Resource Monitoring
```bash
# Check disk space
df -h

# Check memory usage
free -h

# Check CPU usage
top

# Check network connectivity
ping google.com
```

## 🔧 Configuration Issues

### 1. AI Configuration Problems

#### Problem: AI analysis not working
```bash
# Error: AI analysis disabled or unavailable
```

#### Solutions:
```bash
# Check Ollama status
python tools/ai/ollama_preflight.py

# Check AI configuration
python tools/config/config_manager.py show

# Set AI provider
python tools/config/config_manager.py set ai.provider ollama
python tools/config/config_manager.py set ai.ollama.model auto
```

#### Root Cause:
- Ollama not running
- AI configuration disabled
- Missing API keys

### 2. Ghidra Connection Issues

#### Problem: Ghidra MCP connection failed
```bash
# Error: Ghidra MCP not available
```

#### Solutions:
```bash
# Check Ghidra installation
ls -la /opt/ghidra
ls -la C:\ghidra

# Check Ghidra MCP server
curl http://localhost:13337/mcp

# Start Ghidra MCP server
# See Ghidra documentation for MCP setup
```

#### Root Cause:
- Ghidra not installed
- MCP server not running
- Connection configuration issues

### 3. Compiler Issues

#### Problem: Compilation failures
```bash
# Error: gcc not found or compilation failed
```

#### Solutions:
```bash
# Install compiler
# Linux: sudo apt install gcc clang
# macOS: xcode-select --install
# Windows: Install MinGW-w64 or Visual Studio

# Check compiler
gcc --version
clang --version

# Test compilation
echo 'int main(){return 0;}' | gcc -x c - -o test
```

#### Root Cause:
- Compiler not installed
- PATH not set correctly
- Missing build tools

## 🐛 Specific Tool Issues

### 1. Binary Reassembler Issues

#### Problem: Binary reassembly fails
```bash
# Error: Binary reassembly failed
```

#### Solutions:
```bash
# Check original binary
file original.exe
ls -la original.exe

# Check source code
ls -la human_readable_code/
find human_readable_code/ -name "*.c" | head -5

# Test compilation
python tools/quality/compilation_tester.py human_readable_code/

# Check architecture
python tools/binary/binary_reassembler_v2.py --original original.exe --source human_readable_code/ --output rebuilt.exe --arch auto --verbose
```

### 2. AI Analysis Issues

#### Problem: AI analysis not working
```bash
# Error: AI analysis unavailable
```

#### Solutions:
```bash
# Check Ollama
python tools/ai/ollama_preflight.py

# Test Ollama
python tools/ai/ollama_analyzer.py "test code"

# Check configuration
python tools/config/config_manager.py show

# Fallback to heuristics
python reveng_analyzer.py binary.exe --no-enhanced
```

### 3. Web Interface Issues

#### Problem: Web interface not loading
```bash
# Error: Cannot connect to web interface
```

#### Solutions:
```bash
# Check if running
cd web_interface
npm start

# Check ports
netstat -an | grep 3000
netstat -an | grep 5000

# Check dependencies
npm install

# Check logs
docker logs reveng-frontend
docker logs reveng-backend
```

## 🔄 Performance Issues

### 1. Slow Analysis

#### Problem: Analysis taking too long
```bash
# Analysis running for hours
```

#### Solutions:
```bash
# Use smaller files for testing
# Increase timeout values
# Use parallel processing
# Check system resources

# Monitor progress
tail -f *.log

# Kill long-running processes
ps aux | grep python
kill -9 <pid>
```

### 2. Memory Exhaustion

#### Problem: Out of memory errors
```python
# Error: MemoryError
```

#### Solutions:
```bash
# Use streaming for large files
# Increase system memory
# Use smaller chunks
# Clear cache regularly

# Monitor memory
python -c "import psutil; print(psutil.virtual_memory())"
```

### 3. Disk Space Issues

#### Problem: No space left on device
```bash
# Error: No space left on device
```

#### Solutions:
```bash
# Check disk space
df -h

# Clean up generated files
python scripts/maintenance/clean_outputs.py

# Remove old analysis results
rm -rf analysis_*
rm -rf src_optimal_*
rm -rf human_readable_code/
rm -rf deobfuscated_app/
```

## 🆘 Getting Help

### 1. Check Documentation
- [AI Assistant Guide](../docs/guides/AI_ASSISTANT_GUIDE.md)
- [Tool Guide](tool-guide.md)
- [Common Tasks](common-tasks.md)

### 2. Check Logs
```bash
# Main analyzer log
cat reveng_analyzer.log

# Tool-specific logs
cat ai_recompiler_converter.log
cat optimal_binary_analysis.log
```

### 3. Test Individual Components
```bash
# Test language detection
python tools/languages/language_detector.py test_binary.exe

# Test AI analysis
python tools/ai/ollama_preflight.py

# Test Ghidra connection
python tools/config/ghidra_mcp_connector.py
```

### 4. Create Minimal Test Case
```bash
# Create simple test binary
echo 'int main(){return 0;}' > test.c
gcc test.c -o test.exe

# Test analysis
python reveng_analyzer.py test.exe
```

### 5. Report Issues
- [GitHub Issues](https://github.com/oimiragieo/reveng-main/issues)
- Include logs and error messages
- Provide minimal reproduction case
- Specify system information

## 🔧 Advanced Debugging

### 1. Enable Verbose Logging
```python
# Add to tool
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def debug_function():
    logger.debug("Starting function")
    # Function implementation
    logger.debug("Function completed")
```

### 2. Use Debugger
```python
# Add breakpoints
import pdb; pdb.set_trace()

# Or use IDE debugger
# Set breakpoints in problematic code
```

### 3. Profile Performance
```bash
# Profile tool performance
python -m cProfile tools/category/tool_name.py input_file

# Memory profiling
python -m memory_profiler tools/category/tool_name.py input_file
```

### 4. Network Debugging
```bash
# Check network connectivity
ping google.com
curl -I http://localhost:13337/mcp

# Check firewall
sudo ufw status
```

---

**Remember**: Always check logs first, then test individual components, and create minimal test cases for complex issues.
