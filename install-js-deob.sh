#!/usr/bin/env bash
#
# REVENG JavaScript Deobfuscation - Installation Script
#
# This script installs all dependencies needed for the JavaScript
# deobfuscation module.
#

set -e  # Exit on error

echo "========================================================================="
echo "  REVENG v6.0 - JavaScript Deobfuscation Installation"
echo "========================================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if running in project root
if [ ! -f "reveng-js" ]; then
    echo -e "${RED}❌ Error: Please run this script from the reveng-main directory${NC}"
    echo "   cd /path/to/reveng-main && ./install-js-deob.sh"
    exit 1
fi

echo "📦 Step 1/4: Checking Node.js installation..."
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "${GREEN}✅ Node.js found: $NODE_VERSION${NC}"
else
    echo -e "${RED}❌ Node.js not found${NC}"
    echo ""
    echo "Please install Node.js from:"
    echo "  • https://nodejs.org/ (Official)"
    echo "  • Linux: sudo apt install nodejs npm"
    echo "  • macOS: brew install node"
    echo ""
    exit 1
fi

if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm --version)
    echo -e "${GREEN}✅ npm found: $NPM_VERSION${NC}"
else
    echo -e "${RED}❌ npm not found${NC}"
    exit 1
fi

echo ""
echo "📦 Step 2/4: Installing Node.js dependencies..."
echo ""

# Install webcrack (unpacking & unbundling)
echo "Installing webcrack (webpack/browserify unbundling)..."
if npm install -g webcrack 2>&1 | grep -q "up to date\|added"; then
    echo -e "${GREEN}✅ webcrack installed${NC}"
else
    echo -e "${YELLOW}⚠️  webcrack installation had warnings (might still work)${NC}"
fi

# Install prettier (formatting)
echo "Installing prettier (code formatting)..."
if npm list -g prettier &> /dev/null; then
    echo -e "${GREEN}✅ prettier already installed${NC}"
else
    if npm install -g prettier 2>&1 | grep -q "up to date\|added"; then
        echo -e "${GREEN}✅ prettier installed${NC}"
    else
        echo -e "${YELLOW}⚠️  prettier installation had warnings${NC}"
    fi
fi

# Install unuglify-js (ML-based variable renaming)
echo "Installing unuglify-js (ML variable renaming)..."
if npm install -g unuglify-js 2>&1 | grep -q "up to date\|added\|npm ERR!"; then
    if npm list -g unuglify-js &> /dev/null; then
        echo -e "${GREEN}✅ unuglify-js installed${NC}"
    else
        echo -e "${YELLOW}⚠️  unuglify-js failed to install (optional - ML features will be disabled)${NC}"
        echo "   You can continue without it, or try: npm install -g unuglify-js"
    fi
fi

echo ""
echo "📦 Step 3/4: Installing Python dependencies..."
echo ""

# Check if pip is available
if command -v pip &> /dev/null || command -v pip3 &> /dev/null; then
    PIP_CMD=$(command -v pip3 || command -v pip)
    echo -e "${GREEN}✅ pip found${NC}"

    # Install Python dependencies
    echo "Installing Python packages (this may take a minute)..."
    if [ -f "requirements.txt" ]; then
        $PIP_CMD install -r requirements.txt --quiet 2>&1 | tail -1
        echo -e "${GREEN}✅ Python dependencies installed${NC}"
    else
        echo -e "${YELLOW}⚠️  requirements.txt not found, skipping Python dependencies${NC}"
    fi
else
    echo -e "${RED}❌ pip not found${NC}"
    echo "Please install Python 3 and pip"
    exit 1
fi

echo ""
echo "📦 Step 4/4: Verifying installation..."
echo ""

# Check webcrack
if command -v webcrack &> /dev/null; then
    echo -e "${GREEN}✅ webcrack: OK${NC}"
else
    echo -e "${YELLOW}⚠️  webcrack: Not found (unpacking disabled)${NC}"
fi

# Check prettier
if command -v prettier &> /dev/null; then
    echo -e "${GREEN}✅ prettier: OK${NC}"
else
    echo -e "${YELLOW}⚠️  prettier: Not found (formatting disabled)${NC}"
fi

# Check unuglify-js
if command -v unuglify-js &> /dev/null; then
    echo -e "${GREEN}✅ unuglify-js: OK${NC}"
else
    echo -e "${YELLOW}⚠️  unuglify-js: Not found (ML renaming disabled)${NC}"
fi

# Check Python imports
echo -n "Checking Python imports... "
if python3 -c "import sys; sys.path.insert(0, 'src'); from reveng.javascript.deobfuscator import JavaScriptDeobfuscator" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "There may be an issue with Python dependencies"
fi

echo ""
echo "========================================================================="
echo -e "${GREEN}✅ Installation Complete!${NC}"
echo "========================================================================="
echo ""
echo "📚 Quick Start:"
echo ""
echo "  1. Run the example demo:"
echo "     python examples/javascript_deobfuscation_demo.py"
echo ""
echo "  2. Deobfuscate a file:"
echo "     ./reveng-js deobfuscate myfile.js -o output.js"
echo ""
echo "  3. Detect obfuscation types:"
echo "     ./reveng-js detect obfuscated.js"
echo ""
echo "  4. Analyze for malware:"
echo "     ./reveng-js analyze suspicious.js"
echo ""
echo "  5. View all options:"
echo "     ./reveng-js --help"
echo ""
echo "📖 Documentation:"
echo "   • README: src/reveng/javascript/README.md"
echo "   • Implementation: V6_0_IMPLEMENTATION_SUMMARY.md"
echo "   • Research: RESEARCH_JAVASCRIPT_DEOBFUSCATION.md"
echo ""
echo "💡 Optional: Set API keys for LLM features (costs money!):"
echo "   export OPENAI_API_KEY=sk-..."
echo "   export ANTHROPIC_API_KEY=sk-ant-..."
echo ""
echo "Happy deobfuscating! 🎉"
echo ""
