# Binary Patching with REVENG

This guide demonstrates how to use REVENG for binary patching and modification.

## Overview

REVENG provides powerful tools for binary patching, including:
- Full disassemble-modify-reassemble workflow
- Binary validation and verification
- Compilation testing
- Behavioral comparison

## Prerequisites

- REVENG installed and configured
- Target binary file
- Compiler toolchain (GCC, Clang, etc.)

## Step-by-Step Patching

### 1. Initial Analysis

```bash
# Analyze target binary
python reveng_analyzer.py target_app.exe

# Check analysis results
ls analysis_target_app/
```

### 2. Code Extraction

```bash
# Extract human-readable code
python tools/core/human_readable_converter_fixed.py

# Check extracted code
ls human_readable_code/
```

### 3. Code Modification

```bash
# Edit the extracted code
# Use your preferred editor to modify the code
# Example: Add new functionality, fix bugs, remove features

# Check modified code
ls human_readable_code/
```

### 4. Code Formatting

```bash
# Format modified code
python tools/quality/code_formatter.py human_readable_code/

# Check formatted code
ls human_readable_code/
```

### 5. Binary Reconstruction

```bash
# Reassemble modified binary
python tools/core/binary_reassembler_v2.py \
    --original target_app.exe \
    --source human_readable_code/ \
    --output patched_app.exe \
    --arch auto \
    --validation-mode smoke_test
```

### 6. Validation

```bash
# Validate patched binary
python tools/core/binary_validator.py target_app.exe patched_app.exe

# Check validation results
cat validation_report.json
```

## Patching Workflow

### Automated Patching Pipeline

```python
#!/usr/bin/env python3
"""
Automated binary patching pipeline
"""

import subprocess
import json
from pathlib import Path

def patch_binary(binary_path: str, patch_script: str = None):
    """Complete binary patching pipeline"""
    
    binary_name = Path(binary_path).stem
    
    # Step 1: Basic analysis
    print("Step 1: Analyzing target binary")
    subprocess.run([
        "python", "reveng_analyzer.py", binary_path
    ])
    
    # Step 2: Extract code
    print("Step 2: Extracting human-readable code")
    subprocess.run([
        "python", "tools/core/human_readable_converter_fixed.py"
    ])
    
    # Step 3: Apply patches (if script provided)
    if patch_script:
        print("Step 3: Applying patches")
        subprocess.run([
            "python", patch_script, "human_readable_code/"
        ])
    else:
        print("Step 3: Manual patching required")
        print("Edit files in human_readable_code/ and press Enter to continue...")
        input()
    
    # Step 4: Format code
    print("Step 4: Formatting modified code")
    subprocess.run([
        "python", "tools/quality/code_formatter.py", "human_readable_code/"
    ])
    
    # Step 5: Test compilation
    print("Step 5: Testing compilation")
    subprocess.run([
        "python", "tools/quality/compilation_tester.py", "human_readable_code/"
    ])
    
    # Step 6: Reassemble binary
    print("Step 6: Reassembling binary")
    subprocess.run([
        "python", "tools/core/binary_reassembler_v2.py",
        "--original", binary_path,
        "--source", "human_readable_code/",
        "--output", f"patched_{binary_name}.exe",
        "--arch", "auto",
        "--validation-mode", "smoke_test"
    ])
    
    # Step 7: Validate patched binary
    print("Step 7: Validating patched binary")
    subprocess.run([
        "python", "tools/core/binary_validator.py",
        binary_path, f"patched_{binary_name}.exe"
    ])
    
    print("Binary patching complete!")
    print(f"Original: {binary_path}")
    print(f"Patched: patched_{binary_name}.exe")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        patch_script = sys.argv[2] if len(sys.argv) > 2 else None
        patch_binary(sys.argv[1], patch_script)
    else:
        print("Usage: python binary_patching.py <binary_path> [patch_script]")
```

## Common Patching Scenarios

### 1. Bug Fixes

```python
#!/usr/bin/env python3
"""
Bug fix patching script
"""

import os
import re
from pathlib import Path

def fix_buffer_overflow(source_dir: str):
    """Fix buffer overflow vulnerabilities"""
    
    source_path = Path(source_dir)
    
    for c_file in source_path.glob("**/*.c"):
        content = c_file.read_text()
        
        # Replace unsafe functions
        replacements = [
            (r'strcpy\s*\(', 'strncpy('),
            (r'strcat\s*\(', 'strncat('),
            (r'sprintf\s*\(', 'snprintf('),
            (r'gets\s*\(', 'fgets(')
        ]
        
        for pattern, replacement in replacements:
            content = re.sub(pattern, replacement, content)
        
        c_file.write_text(content)
        print(f"Fixed buffer overflow issues in {c_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        fix_buffer_overflow(sys.argv[1])
    else:
        print("Usage: python fix_buffer_overflow.py <source_directory>")
```

### 2. Feature Addition

```python
#!/usr/bin/env python3
"""
Feature addition patching script
"""

import os
from pathlib import Path

def add_logging_feature(source_dir: str):
    """Add logging functionality to recovered code"""
    
    source_path = Path(source_dir)
    
    # Create logging header
    logging_header = """
#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>
#include <time.h>

void log_info(const char* message);
void log_error(const char* message);
void log_debug(const char* message);

#endif
"""
    
    # Create logging implementation
    logging_impl = """
#include "logging.h"
#include <stdio.h>
#include <time.h>

void log_info(const char* message) {
    time_t now = time(0);
    char* time_str = ctime(&now);
    printf("[INFO] %s: %s", time_str, message);
}

void log_error(const char* message) {
    time_t now = time(0);
    char* time_str = ctime(&now);
    printf("[ERROR] %s: %s", time_str, message);
}

void log_debug(const char* message) {
    time_t now = time(0);
    char* time_str = ctime(&now);
    printf("[DEBUG] %s: %s", time_str, message);
}
"""
    
    # Write logging files
    (source_path / "logging.h").write_text(logging_header)
    (source_path / "logging.c").write_text(logging_impl)
    
    print("Added logging feature to recovered code")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        add_logging_feature(sys.argv[1])
    else:
        print("Usage: python add_logging_feature.py <source_directory>")
```

### 3. Security Hardening

```python
#!/usr/bin/env python3
"""
Security hardening patching script
"""

import os
import re
from pathlib import Path

def harden_security(source_dir: str):
    """Apply security hardening patches"""
    
    source_path = Path(source_dir)
    
    for c_file in source_path.glob("**/*.c"):
        content = c_file.read_text()
        
        # Add security headers
        if "#include <stdio.h>" in content:
            content = content.replace(
                "#include <stdio.h>",
                "#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>"
            )
        
        # Add input validation
        content = re.sub(
            r'(\w+)\s*=\s*(\w+)\s*\(([^)]+)\);',
            r'if (validate_input(\3)) {\n    \1 = \2(\3);\n} else {\n    log_error("Invalid input");\n    return -1;\n}',
            content
        )
        
        c_file.write_text(content)
        print(f"Applied security hardening to {c_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        harden_security(sys.argv[1])
    else:
        print("Usage: python harden_security.py <source_directory>")
```

## Advanced Patching Techniques

### 1. Function Hooking

```python
#!/usr/bin/env python3
"""
Function hooking patching script
"""

import os
import re
from pathlib import Path

def add_function_hooks(source_dir: str):
    """Add function hooking capabilities"""
    
    source_path = Path(source_dir)
    
    # Create hook header
    hook_header = """
#ifndef HOOKS_H
#define HOOKS_H

typedef void (*hook_func_t)(void* args);

void register_hook(const char* function_name, hook_func_t hook);
void unregister_hook(const char* function_name);
void call_hooks(const char* function_name, void* args);

#endif
"""
    
    # Create hook implementation
    hook_impl = """
#include "hooks.h"
#include <string.h>
#include <stdlib.h>

typedef struct {
    char* name;
    hook_func_t func;
} hook_entry_t;

static hook_entry_t* hooks = NULL;
static int hook_count = 0;

void register_hook(const char* function_name, hook_func_t hook) {
    hooks = realloc(hooks, (hook_count + 1) * sizeof(hook_entry_t));
    hooks[hook_count].name = strdup(function_name);
    hooks[hook_count].func = hook;
    hook_count++;
}

void unregister_hook(const char* function_name) {
    for (int i = 0; i < hook_count; i++) {
        if (strcmp(hooks[i].name, function_name) == 0) {
            free(hooks[i].name);
            for (int j = i; j < hook_count - 1; j++) {
                hooks[j] = hooks[j + 1];
            }
            hook_count--;
            break;
        }
    }
}

void call_hooks(const char* function_name, void* args) {
    for (int i = 0; i < hook_count; i++) {
        if (strcmp(hooks[i].name, function_name) == 0) {
            hooks[i].func(args);
        }
    }
}
"""
    
    # Write hook files
    (source_path / "hooks.h").write_text(hook_header)
    (source_path / "hooks.c").write_text(hook_impl)
    
    print("Added function hooking capabilities")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        add_function_hooks(sys.argv[1])
    else:
        print("Usage: python add_function_hooks.py <source_directory>")
```

### 2. Performance Optimization

```python
#!/usr/bin/env python3
"""
Performance optimization patching script
"""

import os
import re
from pathlib import Path

def optimize_performance(source_dir: str):
    """Apply performance optimizations"""
    
    source_path = Path(source_dir)
    
    for c_file in source_path.glob("**/*.c"):
        content = c_file.read_text()
        
        # Add inline functions
        content = re.sub(
            r'static\s+(\w+)\s+(\w+)\s*\([^)]*\)\s*\{',
            r'static inline \1 \2(',
            content
        )
        
        # Add loop unrolling hints
        content = re.sub(
            r'for\s*\(\s*int\s+i\s*=\s*0\s*;\s*i\s*<\s*(\d+)\s*;\s*i\+\+\s*\)',
            r'#pragma unroll\n    for (int i = 0; i < \1; i++)',
            content
        )
        
        c_file.write_text(content)
        print(f"Applied performance optimizations to {c_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        optimize_performance(sys.argv[1])
    else:
        print("Usage: python optimize_performance.py <source_directory>")
```

## Validation and Testing

### Binary Validation

```bash
# Validate patched binary
python tools/core/binary_validator.py original.exe patched.exe

# Check validation results
cat validation_report.json
```

### Behavioral Testing

```bash
# Compare behavior
python tools/binary/binary_diff.py original.exe patched.exe

# Generate diff report
python tools/binary/binary_diff.py original.exe patched.exe --output diff_report.json
```

### Performance Testing

```bash
# Test performance
python tools/utils/performance_tester.py original.exe patched.exe

# Generate performance report
python tools/utils/performance_tester.py original.exe patched.exe --output performance_report.json
```

## Best Practices

### Patching Best Practices

1. **Backup original** - Always keep a backup of the original binary
2. **Test thoroughly** - Test patched binary extensively
3. **Validate changes** - Use binary validation tools
4. **Document patches** - Keep detailed records of changes
5. **Version control** - Use version control for patched code

### Security Considerations

1. **Verify integrity** - Check binary integrity after patching
2. **Test security** - Run security tests on patched binary
3. **Review changes** - Review all code changes carefully
4. **Audit trail** - Maintain audit trail of all modifications
5. **Compliance** - Ensure compliance with relevant regulations

## Troubleshooting

### Common Issues

**Compilation Errors:**
```bash
# Check compilation errors
python tools/quality/compilation_tester.py human_readable_code/ --verbose

# Fix common issues
python tools/quality/code_formatter.py human_readable_code/ --fix
```

**Validation Failures:**
```bash
# Check validation errors
python tools/core/binary_validator.py original.exe patched.exe --verbose

# Re-run validation with different mode
python tools/core/binary_validator.py original.exe patched.exe --mode checksum
```

**Behavioral Differences:**
```bash
# Check behavioral differences
python tools/binary/binary_diff.py original.exe patched.exe --verbose

# Generate detailed diff report
python tools/binary/binary_diff.py original.exe patched.exe --output detailed_diff.json
```

## Related Resources

- [Binary Reconstruction Tutorial](../tutorials/binary-reconstruction.md)
- [Code Quality Guide](../tutorials/code-quality.md)
- [Testing Guide](../tutorials/testing.md)
- [Security Analysis](../tutorials/security-analysis.md)

## Support

For binary patching support:
- Check [Troubleshooting Guide](../../.ai/troubleshooting.md)
- Review [Developer Guide](../../docs/DEVELOPER_GUIDE.md)
- Contact development team for complex patching
