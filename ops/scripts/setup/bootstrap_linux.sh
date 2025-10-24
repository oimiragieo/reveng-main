#!/bin/bash
# REVENG Linux Bootstrap Script
# ==============================
#
# Automatically installs required toolchain components on Linux
#
# Requirements:
#   - Python 3.8+ already installed
#   - sudo access for package installation
#
# Usage:
#   bash scripts/bootstrap_linux.sh
#   bash scripts/bootstrap_linux.sh --no-compiler   (skip compiler install)

set -e  # Exit on error

echo ""
echo "========================================"
echo "REVENG Linux Bootstrap"
echo "========================================"
echo ""

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "[ERROR] Cannot detect Linux distribution"
    exit 1
fi

echo "Detected distribution: $DISTRO"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 not found!"
    echo "Please install Python 3.8+ first"
    exit 1
fi

echo "[OK] Python found"
python3 --version
echo ""

# Install Python packages
echo "========================================"
echo "Installing Python Packages"
echo "========================================"
echo ""

python3 -m pip install --upgrade pip --user

echo "Installing LIEF..."
pip3 install lief --user

echo "Installing Keystone..."
pip3 install keystone-engine --user

echo "Installing Capstone..."
pip3 install capstone --user

echo ""
echo "[OK] Python packages installed"
echo ""

# Install compiler (unless --no-compiler flag)
if [ "$1" == "--no-compiler" ]; then
    echo "Skipping compiler installation"
    exit 0
fi

echo "========================================"
echo "Installing C Compiler"
echo "========================================"
echo ""

case "$DISTRO" in
    ubuntu|debian)
        echo "Installing build-essential for Ubuntu/Debian..."
        sudo apt-get update
        sudo apt-get install -y build-essential gcc g++ clang
        ;;
    fedora|rhel|centos)
        echo "Installing development tools for Fedora/RHEL..."
        sudo dnf groupinstall -y "Development Tools"
        sudo dnf install -y gcc gcc-c++ clang
        ;;
    arch|manjaro)
        echo "Installing base-devel for Arch..."
        sudo pacman -S --needed --noconfirm base-devel clang
        ;;
    *)
        echo "[WARNING] Unknown distribution: $DISTRO"
        echo "Please install gcc/clang manually"
        echo ""
        ;;
esac

echo ""
echo "[OK] Compiler installed"
echo ""

# Run toolchain check
echo "========================================"
echo "Verifying Installation"
echo "========================================"
echo ""

python3 tools/check_toolchain.py

if [ $? -ne 0 ]; then
    echo ""
    echo "[WARNING] Some components are still missing"
    echo "Run: python3 tools/check_toolchain.py --fix"
    echo ""
else
    echo ""
    echo "========================================"
    echo "[SUCCESS] Bootstrap Complete!"
    echo "========================================"
    echo ""
    echo "You can now run:"
    echo "  python3 reveng_analyzer.py binary.elf"
    echo ""
fi
