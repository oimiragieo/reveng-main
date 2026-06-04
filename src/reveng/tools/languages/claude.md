# `claude.md` — `tools/languages`

**Repository path:** `src/reveng/tools/languages/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Language-Specific Analyzers

### `csharp_il_analyzer.py`
- **Summary:** REVENG C# IL Analyzer
- **Classes:**
  - `DotNetAssemblyInfo` — Information about a .NET assembly
  - `ILDisassemblyResult` — Result from IL disassembly
  - `DotNetDetector` — Detects if a file is a .NET assembly
  - `ILDasmRunner` — Runs ildasm.exe to disassemble .NET assemblies to IL code
  - `ILSpyRunner` — Runs ILSpy CLI to decompile .NET assemblies to C# source
  - `DotNetObfuscationDetector` — Detects .NET obfuscation
  - `CSharpILAnalyzer` — Main C# IL analyzer
- **Functions / coroutines:**
  - `def main()` — CLI interface for C# IL analysis

### `java_bytecode_analyzer.py`
- **Summary:** REVENG Java Bytecode Analyzer
- **Classes:**
  - `JavaClassInfo` — Information about a Java class
  - `DecompilationResult` — Results from decompilation
  - `JavaBytecodeAnalyzer` — Analyze Java bytecode and produce decompiled source
- **Functions / coroutines:**
  - `def main()` — Test Java bytecode analyzer

### `java_deobfuscator_advanced.py`
- **Summary:** REVENG Advanced Java Deobfuscator
- **Classes:**
  - `DeobfuscationResult` — Result from deobfuscation process
  - `ControlFlowSimplifier` — Simplifies obfuscated control flow in Java code
  - `StringDecryptor` — Decrypts encrypted strings in obfuscated Java code
  - `DeadCodeEliminator` — Removes dead code (unreachable code, unused variables)
  - `ConstantFolder` — Performs constant folding and propagation
  - `JavaAdvancedDeobfuscator` — Main deobfuscator that combines all techniques
- **Functions / coroutines:**
  - `def main()` — CLI interface for advanced deobfuscation

### `java_project_reconstructor.py`
- **Summary:** REVENG Java Project Reconstructor
- **Classes:**
  - `JavaClass` — Represents a decompiled Java class
  - `ProjectStructure` — Represents reconstructed project structure
  - `JavaProjectReconstructor` — Reconstructs original Java project structure from decompiled code
- **Functions / coroutines:**
  - `def main()` — CLI interface for project reconstruction

### `language_detector.py`
- **Summary:** REVENG Enhanced Language Detector
- **Classes:**
  - `FileTypeInfo` — Information about detected file type
  - `LanguageDetector` — Detect file type and programming language from binary/bytecode files
- **Functions / coroutines:**
  - `def main()` — Test language detector

### `python_bytecode_analyzer.py`
- **Summary:** REVENG Python Bytecode Analyzer
- **Classes:**
  - `PythonBytecodeInfo` — Information about Python bytecode file
  - `DecompilationResult` — Result from Python decompilation
  - `PythonBytecodeDetector` — Detects Python bytecode files and extracts metadata
  - `PythonDecompiler` — Decompiles Python bytecode using multiple decompilers
  - `PythonBytecodeAnalyzer` — Main Python bytecode analyzer
- **Functions / coroutines:**
  - `def main()` — CLI interface for Python bytecode analysis

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
