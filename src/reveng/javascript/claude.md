# Directory: src/reveng/javascript

## Overview
This directory contains specialized tools for JavaScript analysis, deobfuscation, and reverse engineering. It provides capabilities for analyzing obfuscated JavaScript, recovering source maps, detecting malware, and transforming code using Babel.

## Files in This Directory

### __init__.py
- **Purpose**: Package initialization

### cli.py
- **Purpose**: Command-line interface for JavaScript analysis
- **Key Functions**: CLI commands for JS deobfuscation and analysis

### deobfuscator.py
- **Purpose**: JavaScript deobfuscation engine
- **Key Classes**: `JavaScriptDeobfuscator`
- **Key Functions**:
  - `deobfuscate()`: Remove obfuscation from JavaScript
  - `unpack()`: Unpack packed JavaScript
  - `beautify()`: Format and beautify code
  - `rename_variables()`: Rename obfuscated variables

### detectors.py
- **Purpose**: Detect obfuscation techniques and patterns
- **Key Classes**: `ObfuscationDetector`
- **Key Functions**:
  - `detect_obfuscation()`: Detect if JS is obfuscated
  - `identify_obfuscator()`: Identify obfuscation tool used
  - `detect_packing()`: Detect if JS is packed

### malware_detector.py
- **Purpose**: Detect malicious JavaScript
- **Key Classes**: `JavaScriptMalwareDetector`
- **Key Functions**:
  - `detect_malware()`: Check if JS is malicious
  - `extract_iocs()`: Extract indicators of compromise
  - `analyze_behavior()`: Analyze JavaScript behavior

### source_map_recoverer.py
- **Purpose**: Recover source maps for minified JavaScript
- **Key Classes**: `SourceMapRecoverer`
- **Key Functions**:
  - `recover_source_map()`: Attempt to recover original source
  - `find_source_map()`: Locate source map files
  - `apply_source_map()`: Apply source map to minified code

### babel_transformer.py
- **Purpose**: Transform JavaScript using Babel
- **Key Classes**: `BabelTransformer`
- **Key Functions**:
  - `transform()`: Transform modern JS to compatible version
  - `transpile()`: Transpile between JS versions
  - `parse_ast()`: Parse JavaScript AST

### cache_system.py
- **Purpose**: Caching system for JavaScript analysis results
- **Key Classes**: `CacheSystem`
- **Key Functions**: Cache and retrieve analysis results

## Architecture

```
┌─────────────────────────────────────┐
│   JavaScript Analysis               │
├─────────────────────────────────────┤
│ • Deobfuscation                     │
│ • Malware Detection                 │
│ • Source Map Recovery               │
│ • AST Manipulation                  │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────────────┐
       │   Analysis Tools       │
       ├────────────────────────┤
       │ • Babel (AST)          │
       │ • Pattern matching     │
       │ • Behavioral analysis  │
       └────────────────────────┘
```

## Key Concepts

### JavaScript Obfuscation Types
- **String encoding**: Base64, hex, unicode escapes
- **Control flow flattening**: Obfuscated logic flow
- **Dead code injection**: Dummy code
- **Variable renaming**: Meaningless variable names
- **Packing**: Self-extracting JavaScript

### Deobfuscation Techniques
- AST-based transformation
- Pattern matching and replacement
- Control flow reconstruction
- Variable name recovery
- String decoding

### Malware Detection
- Suspicious API usage (eval, document.write)
- Obfuscation indicators
- Known malware patterns
- Behavioral analysis (redirects, data exfiltration)

## Usage Examples

### Deobfuscation
```python
from reveng.javascript.deobfuscator import JavaScriptDeobfuscator

deobfuscator = JavaScriptDeobfuscator()

# Read obfuscated JavaScript
with open("obfuscated.js") as f:
    obfuscated_code = f.read()

# Deobfuscate
deobfuscated = deobfuscator.deobfuscate(obfuscated_code)

# Beautify
beautified = deobfuscator.beautify(deobfuscated)

print(beautified)
```

### Malware Detection
```python
from reveng.javascript.malware_detector import JavaScriptMalwareDetector

detector = JavaScriptMalwareDetector()

# Analyze JavaScript
result = detector.detect_malware("suspicious.js")

if result.is_malicious:
    print(f"Malware detected!")
    print(f"Threat level: {result.threat_level}")
    print(f"IOCs: {result.iocs}")
    print(f"Behaviors: {result.behaviors}")
```

### Source Map Recovery
```python
from reveng.javascript.source_map_recoverer import SourceMapRecoverer

recoverer = SourceMapRecoverer()

# Try to recover source
original = recoverer.recover_source_map(
    minified_file="bundle.min.js",
    source_map_url="bundle.min.js.map"
)

if original:
    print(f"Recovered {len(original)} source files")
```

### Obfuscation Detection
```python
from reveng.javascript.detectors import ObfuscationDetector

detector = ObfuscationDetector()

# Check if obfuscated
is_obfuscated = detector.detect_obfuscation(js_code)

if is_obfuscated:
    # Identify obfuscator
    obfuscator = detector.identify_obfuscator(js_code)
    print(f"Obfuscated with: {obfuscator}")
```

## Configuration

### Deobfuscation Options
```python
config = {
    "max_iterations": 10,
    "decode_strings": True,
    "rename_variables": True,
    "remove_dead_code": True,
    "beautify": True
}

deobfuscator = JavaScriptDeobfuscator(config=config)
```

## Testing

### Unit Tests
```bash
pytest tests/javascript/test_deobfuscator.py
pytest tests/javascript/test_malware_detector.py
pytest tests/javascript/test_source_map.py
```

## Related Modules

### Dependencies
- Babel (JavaScript parser/transformer)
- AST manipulation libraries
- Pattern matching engines

### Used By
- Web application analysis
- Malware analysis
- Security research

## Notes

### Supported Obfuscators
- JavaScript Obfuscator
- UglifyJS
- Webpack
- Closure Compiler
- Custom obfuscators

### Limitations
- Cannot fully deobfuscate all techniques
- Some obfuscation may be irreversible
- Virtual machine obfuscation is challenging
- May produce partially deobfuscated code

### Best Practices
1. Start with detection to identify obfuscation type
2. Use multiple deobfuscation passes
3. Manually review deobfuscated code
4. Cache analysis results for large projects
5. Combine static and dynamic analysis

### Performance
- Simple deobfuscation: <1 second
- Complex obfuscation: 5-30 seconds
- Large files (>1MB): May take minutes
- Use caching for repeated analysis
