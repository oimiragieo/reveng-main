#!/bin/bash
# REVENG environment initialization — idempotent
# NOTE: On Windows, run these commands directly in PowerShell/cmd instead of this script.
# Windows workers: run `pip install -r requirements.txt && pip install yara-python ollama volatility3 pytest-xdist`

set -e

pip install -r requirements.txt
pip install yara-python ollama volatility3 pytest-xdist

# Install Ghidra binary if not already installed
if [ ! -f "external/ghidra-dist/ghidra_12.0.4_PUBLIC/support/analyzeHeadless" ] && \
   [ ! -f "external/ghidra-dist/ghidra_12.0.4_PUBLIC/support/analyzeHeadless.bat" ]; then
  echo "Ghidra binary not found — running install script..."
  python scripts/install_ghidra.py
else
  echo "Ghidra binary already installed."
fi

export PYTHONIOENCODING=utf8
