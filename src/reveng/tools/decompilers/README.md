# Java Decompilers for REVENG

This directory contains Java decompiler JAR files used by the Java bytecode analyzer.

## Quick Setup

Run the automated download script:
```bash
# Windows
cd tools\decompilers
python download_decompilers.py

# Linux/macOS
cd tools/decompilers
python3 download_decompilers.py
```

## Manual Download

If the automated script fails, download manually:

### 1. CFR (Recommended)
**Best for**: Modern Java, lambdas, streams, Java 8+
**License**: MIT
**Download**: https://github.com/leibnitz27/cfr/releases

```bash
wget https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar
# Or use curl:
curl -L -o cfr-0.152.jar https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar
```

**Usage**:
```bash
java -jar cfr-0.152.jar MyClass.class --outputdir ./output
```

### 2. Fernflower (Optional)
**Best for**: Older Java versions, IntelliJ IDEA integration
**License**: Apache 2.0
**Download**: https://github.com/fesh0r/fernflower/releases

```bash
wget https://github.com/fesh0r/fernflower/releases/download/1.0/fernflower.jar
# Or use curl:
curl -L -o fernflower.jar https://github.com/fesh0r/fernflower/releases/download/1.0/fernflower.jar
```

**Usage**:
```bash
java -jar fernflower.jar MyClass.class ./output
```

### 3. Procyon (Optional)
**Best for**: Java 8+ features, excellent type inference
**License**: Apache 2.0
**Download**: https://github.com/mstrobel/procyon/releases

```bash
wget https://github.com/mstrobel/procyon/releases/download/v0.6.0/procyon-decompiler-0.6.0.jar
# Or use curl:
curl -L -o procyon-decompiler-0.6.0.jar https://github.com/mstrobel/procyon/releases/download/v0.6.0/procyon-decompiler-0.6.0.jar
```

**Usage**:
```bash
java -jar procyon-decompiler-0.6.0.jar MyClass.class -o ./output
```

## Verification

After downloading, verify the JARs:
```bash
# Test CFR
java -jar cfr-0.152.jar --help

# Test Fernflower (if downloaded)
java -jar fernflower.jar

# Test Procyon (if downloaded)
java -jar procyon-decompiler-0.6.0.jar --help
```

## Expected Files

After setup, this directory should contain:
```
tools/decompilers/
├── README.md (this file)
├── download_decompilers.py
├── cfr-0.152.jar (required)
├── fernflower.jar (optional)
└── procyon-decompiler-0.6.0.jar (optional)
```

## Troubleshooting

**"command not found: wget"**
- Windows: Use `curl -L -o filename.jar URL` or download via browser
- Linux: `sudo apt install wget`
- macOS: `brew install wget`

**"Unable to access jarfile"**
- Ensure you're in the `tools/decompilers` directory
- Check file was downloaded: `ls -lh *.jar`
- Verify file isn't corrupted: file size should be > 1MB

**"UnsupportedClassVersionError"**
- Update Java to version 11 or later: `java -version`

## License Information

- **CFR**: MIT License - https://github.com/leibnitz27/cfr/blob/master/LICENSE
- **Fernflower**: Apache 2.0 - https://github.com/fesh0r/fernflower/blob/master/LICENSE
- **Procyon**: Apache 2.0 - https://github.com/mstrobel/procyon/blob/master/LICENSE

These are third-party tools. REVENG is not affiliated with their authors.

## Advanced Configuration

To customize decompiler settings, edit `tools/java_bytecode_analyzer.py`:
```python
def _get_cfr_config(self) -> Dict[str, Any]:
    return {
        'available': True,
        'command': 'java -jar tools/decompilers/cfr-0.152.jar',
        'args': ['--outputdir', '{output}', '--silent']
    }
```

## Support

- CFR issues: https://github.com/leibnitz27/cfr/issues
- Fernflower issues: https://github.com/fesh0r/fernflower/issues
- Procyon issues: https://github.com/mstrobel/procyon/issues
- REVENG issues: Create issue in REVENG repository
