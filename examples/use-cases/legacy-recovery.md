# Legacy Code Recovery with REVENG

This guide demonstrates how to use REVENG for recovering and modernizing legacy code.

## Overview

REVENG excels at recovering source code from legacy binaries, including:
- Old compiled applications
- Proprietary software
- Lost source code
- Legacy libraries

## Prerequisites

- REVENG installed and configured
- Legacy binary files
- Target development environment

## Step-by-Step Recovery

### 1. Initial Analysis

```bash
# Analyze legacy binary
python reveng_analyzer.py legacy_app.exe

# Check analysis results
ls analysis_legacy_app/
```

### 2. Code Extraction

```bash
# Extract human-readable code
python tools/core/human_readable_converter_fixed.py

# Check extracted code
ls human_readable_code/
```

### 3. Code Formatting

```bash
# Format extracted code
python tools/quality/code_formatter.py human_readable_code/

# Check formatted code
ls human_readable_code/
```

### 4. Type Inference

```bash
# Infer types from analysis
python tools/quality/type_inference_engine.py \
    --functions analysis_legacy_app/functions.json \
    --output types.h

# Check inferred types
cat types.h
```

### 5. Deobfuscation

```bash
# Deobfuscate and organize code
python tools/core/deobfuscation_tool.py

# Check deobfuscated code
ls deobfuscated_app/
```

## Recovery Workflow

### Automated Recovery Pipeline

```python
#!/usr/bin/env python3
"""
Automated legacy code recovery pipeline
"""

import subprocess
import json
from pathlib import Path

def recover_legacy_code(binary_path: str):
    """Complete legacy code recovery pipeline"""
    
    binary_name = Path(binary_path).stem
    
    # Step 1: Basic analysis
    print("Step 1: Analyzing legacy binary")
    subprocess.run([
        "python", "reveng_analyzer.py", binary_path
    ])
    
    # Step 2: Extract code
    print("Step 2: Extracting human-readable code")
    subprocess.run([
        "python", "tools/core/human_readable_converter_fixed.py"
    ])
    
    # Step 3: Format code
    print("Step 3: Formatting extracted code")
    subprocess.run([
        "python", "tools/quality/code_formatter.py", "human_readable_code/"
    ])
    
    # Step 4: Infer types
    print("Step 4: Inferring types")
    subprocess.run([
        "python", "tools/quality/type_inference_engine.py",
        "--functions", f"analysis_{binary_name}/functions.json",
        "--output", "types.h"
    ])
    
    # Step 5: Deobfuscate
    print("Step 5: Deobfuscating code")
    subprocess.run([
        "python", "tools/core/deobfuscation_tool.py"
    ])
    
    print("Legacy code recovery complete!")
    print(f"Recovered code in: human_readable_code/")
    print(f"Deobfuscated code in: deobfuscated_app/")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        recover_legacy_code(sys.argv[1])
    else:
        print("Usage: python legacy_recovery.py <binary_path>")
```

## Language-Specific Recovery

### Java Bytecode Recovery

```bash
# Analyze Java application
python tools/languages/java_bytecode_analyzer.py legacy_app.jar

# Reconstruct Maven project
python tools/languages/java_project_reconstructor.py legacy_app.jar

# Advanced deobfuscation
python tools/languages/java_deobfuscator_advanced.py decompiled/
```

### C# .NET Recovery

```bash
# Analyze .NET assembly
python tools/languages/csharp_il_analyzer.py legacy_app.exe

# Extract IL code
python tools/languages/csharp_il_analyzer.py legacy_app.exe --extract-il

# Reconstruct project
python tools/languages/csharp_il_analyzer.py legacy_app.exe --reconstruct
```

### Python Bytecode Recovery

```bash
# Analyze Python bytecode
python tools/languages/python_bytecode_analyzer.py legacy_script.pyc

# Decompile to source
python tools/languages/python_bytecode_analyzer.py legacy_script.pyc --decompile
```

## Code Quality Improvement

### Automated Code Cleanup

```python
#!/usr/bin/env python3
"""
Legacy code quality improvement
"""

import subprocess
from pathlib import Path

def improve_code_quality(source_dir: str):
    """Improve quality of recovered legacy code"""
    
    source_path = Path(source_dir)
    
    if not source_path.exists():
        print(f"Source directory not found: {source_dir}")
        return
    
    # Step 1: Format code
    print("Step 1: Formatting code")
    subprocess.run([
        "python", "tools/quality/code_formatter.py", str(source_path)
    ])
    
    # Step 2: Test compilation
    print("Step 2: Testing compilation")
    subprocess.run([
        "python", "tools/quality/compilation_tester.py", str(source_path)
    ])
    
    # Step 3: Generate documentation
    print("Step 3: Generating documentation")
    subprocess.run([
        "python", "tools/utils/educational_content_generator.py",
        "--input", str(source_path),
        "--output", "documentation/"
    ])
    
    print("Code quality improvement complete!")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        improve_code_quality(sys.argv[1])
    else:
        print("Usage: python improve_code_quality.py <source_directory>")
```

## Project Reconstruction

### Maven Project Reconstruction

```bash
# Reconstruct Maven project from JAR
python tools/languages/java_project_reconstructor.py legacy_app.jar

# Check reconstructed project
ls reconstructed_project/
cat reconstructed_project/pom.xml
```

### Gradle Project Reconstruction

```bash
# Reconstruct Gradle project
python tools/languages/java_project_reconstructor.py legacy_app.jar --build-system gradle

# Check reconstructed project
ls reconstructed_project/
cat reconstructed_project/build.gradle
```

### Visual Studio Project Reconstruction

```bash
# Reconstruct Visual Studio project
python tools/languages/csharp_il_analyzer.py legacy_app.exe --reconstruct-vs

# Check reconstructed project
ls reconstructed_project/
cat reconstructed_project/legacy_app.csproj
```

## Modernization Strategies

### Code Modernization

```python
#!/usr/bin/env python3
"""
Legacy code modernization
"""

import json
from pathlib import Path

def modernize_legacy_code(source_dir: str):
    """Modernize recovered legacy code"""
    
    source_path = Path(source_dir)
    
    # Identify modernization opportunities
    modernization_plan = {
        "deprecated_functions": [],
        "security_issues": [],
        "performance_improvements": [],
        "modern_patterns": []
    }
    
    # Scan for deprecated functions
    for c_file in source_path.glob("**/*.c"):
        content = c_file.read_text()
        
        # Check for deprecated functions
        deprecated = ["gets", "strcpy", "sprintf"]
        for func in deprecated:
            if func in content:
                modernization_plan["deprecated_functions"].append({
                    "file": str(c_file),
                    "function": func,
                    "recommendation": f"Replace {func} with safer alternative"
                })
    
    # Save modernization plan
    with open("modernization_plan.json", "w") as f:
        json.dump(modernization_plan, f, indent=2)
    
    print("Modernization plan generated: modernization_plan.json")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        modernize_legacy_code(sys.argv[1])
    else:
        print("Usage: python modernize_legacy_code.py <source_directory>")
```

## Testing Recovered Code

### Compilation Testing

```bash
# Test compilation of recovered code
python tools/quality/compilation_tester.py human_readable_code/

# Test with specific compiler
python tools/quality/compilation_tester.py human_readable_code/ --compiler gcc
```

### Functional Testing

```bash
# Generate test cases
python tools/utils/educational_content_generator.py \
    --input human_readable_code/ \
    --output tests/ \
    --generate-tests

# Run generated tests
python -m pytest tests/
```

## Documentation Generation

### API Documentation

```bash
# Generate API documentation
python tools/utils/educational_content_generator.py \
    --input human_readable_code/ \
    --output docs/ \
    --generate-api-docs

# Check generated documentation
ls docs/
```

### User Manual

```bash
# Generate user manual
python tools/utils/training_material_generator.py \
    --input human_readable_code/ \
    --output manual/ \
    --format markdown

# Check generated manual
ls manual/
```

## Best Practices

### Recovery Best Practices

1. **Start with simple binaries** - Begin with uncomplicated applications
2. **Use multiple tools** - Combine different analysis approaches
3. **Validate results** - Test recovered code thoroughly
4. **Document findings** - Keep detailed records of the recovery process
5. **Iterate and improve** - Refine the recovery process

### Code Quality Best Practices

1. **Format consistently** - Use consistent code formatting
2. **Add documentation** - Document recovered functions and classes
3. **Test thoroughly** - Create comprehensive test suites
4. **Modernize gradually** - Update code incrementally
5. **Maintain compatibility** - Ensure backward compatibility

## Troubleshooting

### Common Issues

**Compilation Errors:**
```bash
# Check for missing dependencies
python tools/quality/compilation_tester.py human_readable_code/ --verbose

# Fix common issues
python tools/quality/code_formatter.py human_readable_code/ --fix
```

**Missing Functions:**
```bash
# Generate missing implementations
python tools/core/implementation_tool.py

# Check generated implementations
ls implementations/
```

**Type Issues:**
```bash
# Re-run type inference
python tools/quality/type_inference_engine.py \
    --functions analysis_legacy_app/functions.json \
    --output types.h \
    --ai-enhanced
```

## Related Resources

- [Binary Reconstruction Tutorial](../tutorials/binary-reconstruction.md)
- [Code Quality Guide](../tutorials/code-quality.md)
- [Testing Guide](../tutorials/testing.md)
- [Documentation Generation](../tutorials/documentation.md)

## Support

For legacy code recovery support:
- Check [Troubleshooting Guide](../../.ai/troubleshooting.md)
- Review [Developer Guide](../../docs/DEVELOPER_GUIDE.md)
- Contact development team for complex recovery
