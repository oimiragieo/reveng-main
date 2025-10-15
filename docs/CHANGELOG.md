# REVENG Changelog

All notable changes to this project are documented here.

## [2.0.0] - 2025-01-27 - Universal Multi-Language Platform

Major release transforming REVENG into a universal reverse engineering platform.

### Added

**Phase 3: Multi-Language & Enterprise Features**
- C# .NET assembly analyzer with IL disassembly (ildasm) and C# decompilation (ILSpy)
- Python bytecode analyzer supporting Python 2.7-3.12 with multiple decompilers
- Java project reconstructor generating Maven/Gradle projects from JARs
- Advanced Java deobfuscator with 4 techniques (control flow, strings, dead code, constants)
- Interactive code visualizations (vis.js HTML graphs, Graphviz PNG exports)
- Enterprise audit trails (SOC 2 / ISO 27001 compliant logging)
- Extensible plugin system with hook architecture
- GPU acceleration for compute-intensive operations (CUDA/OpenCL/Metal)
- C# obfuscation detection (ConfuserEx, .NET Reactor, Eazfuscator)
- Python obfuscation detection (PyArmor, Nuitka)
- Comprehensive integration of all analyzers into main pipeline

**Phase 2: AI Enhancement & Deobfuscation**
- AI-enhanced Java analysis with Ollama integration
- ProGuard mapping file parser for deobfuscation
- Security vulnerability detection via LLMs
- AI-powered name suggestions for obfuscated code
- Multi-provider AI support (Ollama, Anthropic, OpenAI)
- Batch analysis support
- Confidence-scored AI recommendations

**Phase 1: Java Bytecode Support**
- Universal language detection system (Java, C#, Python, Native)
- Java bytecode analyzer with multi-decompiler support (CFR, Fernflower, Procyon)
- Obfuscation detection (ProGuard, Allatori)
- Automated decompiler setup and download
- JAR/WAR/EAR archive support
- Java-specific analysis pipeline

### Changed
- Main pipeline (`reveng_analyzer.py`) now routes to 4 language analyzers
- Configuration system expanded for multi-language support
- Output structure reorganized for language-specific results
- Documentation restructured into docs/ folder

### Performance
- Java analysis: <10s for 10MB JARs
- C# analysis: <5s for typical .NET assemblies
- Python analysis: <3s for typical .pyc files
- GPU acceleration for pattern matching and hash operations

### Statistics
- **4 languages** fully supported
- **8 decompilers** integrated
- **3 AI providers** supported
- **25+ files** created
- **10,000+ lines** of new code
- **23 major features** implemented

---

## [1.5.0] - 2025-01-20 - Native Binary Analysis Enhancements

### Added
- Enhanced GhidraMCP integration (16 MCP features)
- Crypto pattern detection
- Call graph analysis
- Domain-based code organization (6 domains)
- Human-readable code conversion
- Deobfuscation tool

### Improved
- Analysis accuracy through AI assistance
- Function categorization
- Output structure (30+ categorized folders)

---

## [1.0.0] - 2025-01-15 - Initial Release

### Added
- 7-step universal binary analysis pipeline
- GhidraMCP integration for native binaries
- AI-powered function analysis
- Comprehensive disassembly
- Specification document generation
- Multi-architecture support (x86, x86_64, ARM, ARM64)

### Features
- PE/ELF/Mach-O binary support
- Ghidra decompilation
- AI recompiler with confidence scoring
- Optimal binary analysis (100+ functions)
- Source code inspection
- Implementation tool for missing features

---

## Version History Summary

| Version | Date | Focus | Files Added | Languages |
|---------|------|-------|-------------|-----------|
| 1.0.0 | 2025-01-15 | Native binaries | 5 | 1 (Native) |
| 1.5.0 | 2025-01-20 | Enhancements | 3 | 1 (Native) |
| 2.0.0 | 2025-01-27 | Multi-language | 25+ | 4 (Java/C#/Python/Native) |

---

## Roadmap

### Version 2.1.0 (Planned)
- Android APK support (DEX file analysis)
- JD-GUI decompiler integration
- JAR signing analysis
- Enhanced visualization features
- Performance optimizations

### Version 2.5.0 (Future)
- Swift/Objective-C support
- Rust binary analysis
- Go binary analysis
- Enhanced machine learning for malware classification

### Version 3.0.0 (Future)
- Web interface (FastAPI + Streamlit)
- Cloud deployment support
- Multi-binary correlation
- Automated vulnerability discovery
- Threat intelligence integration

---

## Breaking Changes

### 2.0.0
- Configuration file structure changed (added multi-language sections)
- Output folder structure changed (language-specific subfolders)
- API changes in main pipeline (new routing methods)

### Migration Guide (1.x → 2.0)

**Configuration**:
```yaml
# Old (1.x)
analysis:
  enable_ai: true

# New (2.0)
analysis:
  enable_ai: true
  fallback_to_heuristics: true  # New option
```

**Output Structure**:
```
# Old (1.x)
analysis_binary/
  └── src_optimal_analysis/

# New (2.0)
analysis_binary/
  ├── java_analysis/       (if JAR)
  ├── csharp_analysis/     (if .NET)
  ├── python_analysis/     (if .pyc)
  └── src_optimal_analysis/ (if native)
```

**API Changes**:
```python
# Old (1.x)
analyzer = REVENGAnalyzer(binary_path)
result = analyzer.analyze()  # Always used Ghidra

# New (2.0)
analyzer = REVENGAnalyzer(binary_path)
result = analyzer.analyze()  # Auto-routes to appropriate analyzer
```

---

## Credits

### Contributors
- Primary development by core team
- Community contributions welcome

### Third-Party Tools
- **Ghidra** - National Security Agency
- **CFR** - Lee Benfield
- **Fernflower** - JetBrains
- **Procyon** - Mike Strobel
- **ILSpy** - ic#code team
- **uncompyle6** - Rocky Bernstein
- **Ollama** - Ollama team

### Libraries
- LIEF - Binary parsing
- Keystone - Multi-arch assembler
- Capstone - Multi-arch disassembler
- NetworkX - Graph algorithms
- vis.js - Interactive visualizations

---

## Support

For issues and feature requests:
- Create GitHub issue
- Check documentation in docs/
- Review troubleshooting guides

---

## License

See LICENSE file for details.
