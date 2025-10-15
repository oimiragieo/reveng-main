#!/usr/bin/env python3
"""Test functional code generator with AI"""

import sys
import json
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from tools.functional_code_generator import FunctionalCodeGenerator

# Load test data
with open('test_disasm.asm', 'r') as f:
    disassembly = f.read()

with open('test_analysis.json', 'r') as f:
    analysis = json.load(f)

# Create generator with AI enabled
print("Creating functional code generator with AI...")
generator = FunctionalCodeGenerator(use_ai=True)

print(f"AI enabled: {generator.use_ai}")
print(f"AI analyzer: {generator.ai_analyzer}")

if generator.ai_analyzer:
    print(f"Model: {generator.ai_analyzer.model_name}")

# Generate code
print("\nGenerating functional code...")
code = generator.generate_functional_code(
    function_name="file_encrypt",
    disassembly=disassembly,
    analysis=analysis,
    output_path=Path("test_generated_ai.c")
)

print("\nGenerated code:")
print("=" * 70)
print(code)
print("=" * 70)

print(f"\nOutput written to: test_generated_ai.c")
