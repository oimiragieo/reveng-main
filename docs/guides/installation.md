# REVENG Installation Guide

This guide provides detailed installation instructions for the REVENG Universal Reverse Engineering Platform on Windows, Linux, and macOS.

## 📋 System Requirements

### Minimum Requirements
- **Python**: 3.11 or higher
- **RAM**: 4GB (8GB recommended)
- **Storage**: 2GB free space
- **OS**: Windows 10+, Ubuntu 20.04+, macOS 10.15+

### Recommended Requirements
- **Python**: 3.12
- **RAM**: 16GB
- **Storage**: 10GB free space
- **CPU**: 4+ cores
- **GPU**: NVIDIA GPU with CUDA support (optional, for AI features)

## 🪟 Windows Installation

### Method 1: Automated Installation (Recommended)

1. **Download and run the bootstrap script:**
   ```cmd
   # Download the repository
   git clone https://github.com/oimiragieo/reveng-main.git
   cd reveng-main
   
   # Run the Windows bootstrap script
   scripts\bootstrap_windows.bat
   ```

2. **Verify installation:**
   ```cmd
   python reveng_analyzer.py --help
   ```

### Method 2: Manual Installation

1. **Install Python 3.11+:**
   - Download from [python.org](https://www.python.org/downloads/)
   - Ensure "Add Python to PATH" is checked
   - Install pip if not included

2. **Install Java 21 (for Ghidra integration):**
   - Download from [Oracle](https://www.oracle.com/java/technologies/downloads/) or [OpenJDK](https://adoptium.net/)
   - Add to system PATH

3. **Install Ghidra (optional but recommended):**
   - Download from [GitHub](https://github.com/NationalSecurityAgency/ghidra/releases)
   - Extract to `C:\ghidra`
   - Set environment variable: `GHIDRA_INSTALL_DIR=C:\ghidra`

4. **Install Visual Studio Build Tools:**
   - Download from [Microsoft](https://visualstudio.microsoft.com/downloads/)
   - Install "C++ build tools" workload

5. **Install REVENG:**
   ```cmd
   # Clone repository
   git clone https://github.com/oimiragieo/reveng-main.git
   cd reveng-main
   
   # Install Python dependencies
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   
   # Verify installation
   python tools/check_toolchain.py --fix
   ```

## 🐧 Linux Installation

### Ubuntu/Debian

1. **Install system dependencies:**
   ```bash
   sudo apt update
   sudo apt install python3.11 python3.11-pip python3.11-venv
   sudo apt install openjdk-21-jdk
   sudo apt install gcc g++ clang clang-format cppcheck
   sudo apt install git curl wget
   ```

2. **Install Ghidra (optional):**
   ```bash
   # Download and install Ghidra
   wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20231221.zip
   unzip ghidra_11.0.1_PUBLIC_20231221.zip
   sudo mv ghidra_11.0.1_PUBLIC /opt/ghidra
   echo 'export GHIDRA_INSTALL_DIR=/opt/ghidra' >> ~/.bashrc
   ```

3. **Install REVENG:**
   ```bash
   # Clone repository
   git clone https://github.com/oimiragieo/reveng-main.git
   cd reveng-main
   
   # Create virtual environment
   python3.11 -m venv venv
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   
   # Run bootstrap script
   chmod +x scripts/bootstrap_linux.sh
   ./scripts/bootstrap_linux.sh
   ```

### CentOS/RHEL/Fedora

1. **Install system dependencies:**
   ```bash
   # CentOS/RHEL
   sudo yum install python311 python311-pip java-21-openjdk-devel gcc gcc-c++ clang
   
   # Fedora
   sudo dnf install python3.11 python3.11-pip java-21-openjdk-devel gcc gcc-c++ clang
   ```

2. **Install REVENG:**
   ```bash
   # Follow same steps as Ubuntu
   git clone https://github.com/oimiragieo/reveng-main.git
   cd reveng-main
   python3.11 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### Arch Linux

1. **Install dependencies:**
   ```bash
   sudo pacman -S python python-pip jdk-openjdk gcc clang
   ```

2. **Install REVENG:**
   ```bash
   # Follow same steps as Ubuntu
   ```

## 🍎 macOS Installation

### Method 1: Using Homebrew (Recommended)

1. **Install Homebrew:**
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install dependencies:**
   ```bash
   brew install python@3.11 openjdk@21 gcc clang-format
   ```

3. **Install REVENG:**
   ```bash
   git clone https://github.com/oimiragieo/reveng-main.git
   cd reveng-main
   python3.11 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### Method 2: Manual Installation

1. **Install Python 3.11+:**
   - Download from [python.org](https://www.python.org/downloads/)
   - Or use pyenv: `brew install pyenv && pyenv install 3.11.5`

2. **Install Java 21:**
   ```bash
   brew install openjdk@21
   echo 'export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"' >> ~/.zshrc
   ```

3. **Install Xcode Command Line Tools:**
   ```bash
   xcode-select --install
   ```

4. **Install REVENG:**
   ```bash
   # Follow same steps as Homebrew method
   ```

## 🐳 Docker Installation

### Quick Start with Docker

1. **Clone repository:**
   ```bash
   git clone https://github.com/oimiragieo/reveng-main.git
   cd reveng-main
   ```

2. **Build Docker image:**
   ```bash
   docker build -t reveng .
   ```

3. **Run REVENG:**
   ```bash
   docker run -v $(pwd):/workspace reveng python reveng_analyzer.py /workspace/binary.exe
   ```

### Docker Compose (Web Interface)

1. **Start web interface:**
   ```bash
   cd web_interface
   docker-compose up -d
   ```

2. **Access web interface:**
   - Open http://localhost:3000 in your browser

## 🔧 Verification

### Check Installation

1. **Verify Python installation:**
   ```bash
   python --version
   # Should show Python 3.11.x or higher
   ```

2. **Verify Java installation:**
   ```bash
   java --version
   # Should show Java 21.x.x
   ```

3. **Verify REVENG installation:**
   ```bash
   python reveng_analyzer.py --help
   python tools/check_toolchain.py --check-only
   ```

4. **Run test suite:**
   ```bash
   python -m pytest tests/ -v
   ```

### Test with Sample Binary

1. **Create a test binary:**
   ```bash
   # Create a simple C program
   echo 'int main() { return 0; }' > test.c
   gcc test.c -o test
   ```

2. **Analyze the binary:**
   ```bash
   python reveng_analyzer.py test
   ```

3. **Check results:**
   ```bash
   ls -la analysis_test/
   ```

## 🚨 Troubleshooting

### Common Issues

#### Python Version Issues
```bash
# If you have multiple Python versions
python3.11 -m pip install -r requirements.txt
python3.11 reveng_analyzer.py --help
```

#### Java/Ghidra Issues
```bash
# Check Java installation
java --version
javac --version

# Set JAVA_HOME if needed
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
```

#### Permission Issues (Linux/macOS)
```bash
# Make scripts executable
chmod +x scripts/*.sh
chmod +x tools/*.py
```

#### Memory Issues
```bash
# Increase Python memory limit
export PYTHONHASHSEED=0
python -X dev reveng_analyzer.py binary.exe
```

#### Network Issues
```bash
# Use different pip index
pip install -r requirements.txt -i https://pypi.org/simple/
```

### Windows-Specific Issues

#### Path Issues
```cmd
# Add Python to PATH
set PATH=%PATH%;C:\Python311;C:\Python311\Scripts

# Add Java to PATH
set PATH=%PATH%;C:\Program Files\Java\jdk-21\bin
```

#### Visual Studio Build Tools
```cmd
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/
# Select "C++ build tools" workload
```

### Linux-Specific Issues

#### Missing Development Headers
```bash
# Ubuntu/Debian
sudo apt install python3.11-dev libffi-dev libssl-dev

# CentOS/RHEL
sudo yum install python311-devel libffi-devel openssl-devel
```

#### Permission Denied
```bash
# Fix permissions
sudo chown -R $USER:$USER ~/.local
chmod -R 755 ~/.local
```

### macOS-Specific Issues

#### Xcode Command Line Tools
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Accept license
sudo xcodebuild -license accept
```

#### Homebrew Issues
```bash
# Fix Homebrew permissions
sudo chown -R $(whoami) /opt/homebrew
```

## 🔄 Updates

### Updating REVENG

1. **Pull latest changes:**
   ```bash
   git pull origin main
   ```

2. **Update dependencies:**
   ```bash
   pip install -r requirements.txt --upgrade
   ```

3. **Verify installation:**
   ```bash
   python tools/check_toolchain.py --check-only
   ```

### Updating Dependencies

1. **Update Python packages:**
   ```bash
   pip list --outdated
   pip install --upgrade package_name
   ```

2. **Update system packages:**
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt upgrade
   
   # macOS
   brew update && brew upgrade
   ```

## 🆘 Getting Help

### Documentation
- **[User Guide](docs/USER_GUIDE.md)** - Complete usage documentation
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)** - Development workflows
- **[API Reference](API_REFERENCE.md)** - Python API documentation

### Community Support
- **[GitHub Issues](https://github.com/oimiragieo/reveng-main/issues)** - Bug reports and feature requests
- **[GitHub Discussions](https://github.com/oimiragieo/reveng-main/discussions)** - Questions and community support
- **[Security Issues](https://github.com/oimiragieo/reveng-main/security/advisories/new)** - Report security vulnerabilities

### Professional Support
- **Enterprise Support**: Available for commercial use
- **Training**: Custom training sessions available
- **Consulting**: Professional reverse engineering services

---

**Installation completed successfully! 🎉**

Next steps:
1. Read the [Quick Start Guide](docs/QUICK_START.md)
2. Try the [Examples](examples/README.md)
3. Explore the [User Guide](docs/USER_GUIDE.md)
