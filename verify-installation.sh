#!/usr/bin/env bash
#
# REVENG Installation Verification Script
#
# Checks that REVENG is properly installed and working.
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

echo "========================================================================="
echo "  REVENG Installation Verification"
echo "========================================================================="
echo ""

#==============================================================================
# Test Functions
#==============================================================================

test_command() {
    local name="$1"
    local command="$2"
    local required="$3"  # "required" or "optional"

    echo -n "Testing $name... "

    if eval "$command" &> /dev/null; then
        echo -e "${GREEN}PASS${NC}"
        ((PASS++))
        return 0
    else
        if [ "$required" = "required" ]; then
            echo -e "${RED}FAIL${NC}"
            ((FAIL++))
            return 1
        else
            echo -e "${YELLOW}SKIP (optional)${NC}"
            ((WARN++))
            return 0
        fi
    fi
}

#==============================================================================
# Core Requirements
#==============================================================================

echo -e "${BLUE}Core Requirements:${NC}"
echo ""

test_command "Python 3.9+" "python3 --version | grep -E 'Python 3\.(9|10|11|12)'" "required"
test_command "pip" "pip --version" "required"
test_command "REVENG package" "pip show reveng 2>/dev/null" "required"
test_command "reveng command" "which reveng" "required"
test_command "reveng --version" "reveng --version" "required"

echo ""

#==============================================================================
# Python Imports
#==============================================================================

echo -e "${BLUE}Python Imports:${NC}"
echo ""

test_command "reveng.analyzer" "python3 -c 'from reveng.analyzer import REVENGAnalyzer'" "required"
test_command "reveng.api" "python3 -c 'from reveng.api import REVENGAPI'" "required"
test_command "reveng.cli" "python3 -c 'from reveng.cli import main'" "required"

echo ""

#==============================================================================
# JavaScript Module
#==============================================================================

echo -e "${BLUE}JavaScript Module:${NC}"
echo ""

test_command "reveng-js script" "[ -x reveng-js ]" "required"
test_command "JavaScript imports" "python3 -c 'import sys; sys.path.insert(0, \"src\"); from reveng.javascript.deobfuscator import JavaScriptDeobfuscator'" "required"
test_command "Node.js" "node --version" "optional"
test_command "npm" "npm --version" "optional"
test_command "webcrack" "which webcrack" "optional"
test_command "prettier" "which prettier" "optional"
test_command "unuglify-js" "which unuglify-js" "optional"

echo ""

#==============================================================================
# Examples
#==============================================================================

echo -e "${BLUE}Examples:${NC}"
echo ""

test_command "my_first_analysis.py" "[ -f examples/my_first_analysis.py ]" "required"
test_command "javascript_deobfuscation_demo.py" "[ -f examples/javascript_deobfuscation_demo.py ]" "required"
test_command "Test samples" "[ -d examples/test-samples ]" "required"

echo ""

#==============================================================================
# Optional Features
#==============================================================================

echo -e "${BLUE}Optional Features:${NC}"
echo ""

test_command "Ghidra server" "[ -f external/ghidra-server/ghidra_http_server.py ]" "optional"
test_command "Java (for Ghidra)" "java --version" "optional"
test_command "Ollama (local LLM)" "which ollama" "optional"
test_command "GEMINI_API_KEY" "[ ! -z \"\$GEMINI_API_KEY\" ]" "optional"
test_command "OPENAI_API_KEY" "[ ! -z \"\$OPENAI_API_KEY\" ]" "optional"
test_command "ANTHROPIC_API_KEY" "[ ! -z \"\$ANTHROPIC_API_KEY\" ]" "optional"

echo ""

#==============================================================================
# Summary
#==============================================================================

echo "========================================================================="
echo -e "${BLUE}Summary:${NC}"
echo "========================================================================="
echo ""
echo -e "  ${GREEN}PASS${NC}: $PASS tests"
echo -e "  ${RED}FAIL${NC}: $FAIL tests"
echo -e "  ${YELLOW}SKIP${NC}: $WARN tests (optional)"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✅ Installation verified successfully!${NC}"
    echo ""
    echo "🎉 You're ready to use REVENG!"
    echo ""
    echo "Quick start:"
    echo "  reveng --help"
    echo "  ./reveng-js --help"
    echo "  python examples/my_first_analysis.py"
    echo ""
    exit 0
else
    echo -e "${RED}❌ Installation has issues. Please fix the failed tests.${NC}"
    echo ""
    echo "Common fixes:"
    echo "  • Run: ./install-reveng.sh"
    echo "  • Run: pip install -e ."
    echo "  • Check: QUICK_START.md"
    echo ""
    exit 1
fi
