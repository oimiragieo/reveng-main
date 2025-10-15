#!/usr/bin/env python3
"""
REVENG Universal Reverse Engineering Platform - Entry Point
==========================================================

This module provides the entry point for running REVENG as a module:
    python -m reveng

Author: REVENG Development Team
Version: 2.1.0
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
