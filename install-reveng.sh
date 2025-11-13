#!/usr/bin/env bash
#
# REVENG - Universal Reverse Engineering Platform
# Complete Installation Script
#
# This script installs EVERYTHING needed for REVENG:
# - Python dependencies
# - REVENG package (reveng command)
# - JavaScript deobfuscation module
# - Verifies installation
#

set -e  # Exit on error

echo "========================================================================="
echo "  REVENG - Universal Reverse Engineering Platform"
echo "  Complete Installation"
echo "========================================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running in project root
if [ ! -f "reveng.py" ] || [ ! -f "pyproject.toml" ]; then
    echo -e "${RED}❌ Error: Please run this script from the reveng-main directory${NC}"
    echo "   cd /path/to/reveng-main && ./install-reveng.sh"
    exit 1
fi

echo -e "${BLUE}📦 Installation Plan:${NC}"
echo "   1. Python dependencies"
echo "   2. REVENG package (reveng command)"
echo "   3. JavaScript deobfuscation module"
echo "   4. Verification"
echo ""
read -p "Continue? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
    echo "Installation cancelled."
    exit 0
fi
echo ""

#==============================================================================
# STEP 1: Python Dependencies
#==============================================================================

echo -e "${BLUE}📦 Step 1/4: Installing Python dependencies...${NC}"
echo ""

if command -v pip &> /dev/null || command -v pip3 &> /dev/null; then
    PIP_CMD=$(command -v pip3 || command -v pip)
    echo -e "${GREEN}✅ pip found: $PIP_CMD${NC}"
else
    echo -e "${RED}❌ pip not found${NC}"
    echo "Please install Python 3.9+ and pip"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
echo "Python version: $PYTHON_VERSION"

if [ -f "requirements.txt" ]; then
    echo "Installing core dependencies..."
    $PIP_CMD install -r requirements.txt --quiet 2>&1 | tail -3
    echo -e "${GREEN}✅ Core dependencies installed${NC}"
else
    echo -e "${YELLOW}⚠️  requirements.txt not found${NC}"
fi

echo ""

#==============================================================================
# STEP 2: Install REVENG Package
#==============================================================================

echo -e "${BLUE}📦 Step 2/4: Installing REVENG package (reveng command)...${NC}"
echo ""

echo "Running: pip install -e ."
$PIP_CMD install -e . --quiet 2>&1 | tail -3

# Verify reveng command was installed
if command -v reveng &> /dev/null; then
    VERSION=$(reveng --version 2>&1)
    echo -e "${GREEN}✅ REVENG package installed: $VERSION${NC}"
else
    echo -e "${RED}❌ Installation failed - reveng command not found${NC}"
    echo "Try running manually: pip install -e ."
    exit 1
fi

echo ""

#==============================================================================
# STEP 3: JavaScript Deobfuscation Module
#==============================================================================

echo -e "${BLUE}📦 Step 3/4: Installing JavaScript deobfuscation module...${NC}"
echo ""

if [ -f "install-js-deob.sh" ]; then
    echo "Running JavaScript deobfuscation installer..."
    bash install-js-deob.sh 2>&1 | grep -E "✅|⚠️|❌|Step|Installing|Checking" || true
    echo -e "${GREEN}✅ JavaScript deobfuscation module installed${NC}"
else
    echo -e "${YELLOW}⚠️  install-js-deob.sh not found, skipping JavaScript module${NC}"
fi

echo ""

#==============================================================================
# STEP 4: Verification
#==============================================================================

echo -e "${BLUE}📦 Step 4/4: Verifying installation...${NC}"
echo ""

# Check reveng command
echo -n "Checking reveng command... "
if reveng --version &> /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Check Python imports
echo -n "Checking Python imports... "
if python3 -c "from reveng.analyzer import REVENGAnalyzer" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Check JavaScript module
echo -n "Checking JavaScript module... "
if [ -x "reveng-js" ] && python3 -c "import sys; sys.path.insert(0, 'src'); from reveng.javascript.deobfuscator import JavaScriptDeobfuscator" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}OPTIONAL${NC}"
fi

# Check Node.js (optional)
echo -n "Checking Node.js (optional)... "
if command -v node &> /dev/null; then
    echo -e "${GREEN}OK ($(node --version))${NC}"
else
    echo -e "${YELLOW}NOT INSTALLED (optional)${NC}"
fi

echo ""
echo "========================================================================="
echo -e "${GREEN}✅ Installation Complete!${NC}"
echo "========================================================================="
echo ""
echo -e "${BLUE}📚 Quick Start:${NC}"
echo ""
echo "  1️⃣  Analyze a binary:"
echo "     reveng analyze /path/to/binary"
echo ""
echo "  2️⃣  Deobfuscate JavaScript:"
echo "     ./reveng-js deobfuscate obfuscated.js -o clean.js"
echo ""
echo "  3️⃣  Run demos:"
echo "     python examples/javascript_deobfuscation_demo.py"
echo ""
echo "  4️⃣  View all commands:"
echo "     reveng --help"
echo "     ./reveng-js --help"
echo ""
echo -e "${BLUE}📖 Documentation:${NC}"
echo "   • Quick Start: QUICK_START.md"
echo "   • JavaScript: src/reveng/javascript/README.md"
echo "   • Full Docs: docs/"
echo ""
echo -e "${BLUE}🔧 Optional Setup:${NC}"
echo "   • Ghidra: For binary disassembly (see INSTALLATION.md)"
echo "   • AI APIs: For LLM features (set OPENAI_API_KEY, ANTHROPIC_API_KEY)"
echo "   • Ollama: For local AI models"
echo ""
echo "Happy reverse engineering! 🎉"
echo ""
