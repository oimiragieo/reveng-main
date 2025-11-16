# REVENG Basic Examples

Simple, easy-to-follow examples for beginners. Start here if you're new to REVENG!

## 📁 Available Examples

### ✅ 01_simple_analysis.py
**What it does:** Analyzes any binary file and shows basic information

**What you'll learn:**
- How to create a REVENGAnalyzer
- How to configure basic analysis options
- How to interpret analysis results

**Requirements:**
- REVENG installed
- No API keys needed
- No Ghidra needed

**Usage:**
```bash
# Analyze system binary
python examples/basic/01_simple_analysis.py /bin/ls

# Analyze custom binary
python examples/basic/01_simple_analysis.py /path/to/your/binary
```

**Time:** ~2 minutes

---

## 📚 Example Progression

We recommend following the examples in order:

1. **01_simple_analysis.py** ← Start here!
   - Basic analysis without AI or Ghidra
   - Learn the fundamentals
   - See what REVENG can do out of the box

2. **More examples coming soon!**
   - Stay tuned for Java, C#, and Python examples
   - Advanced features will be added progressively

---

## 🚀 Quick Start

```bash
# 1. Make sure REVENG is installed
cd /path/to/reveng-main
pip install -e .

# 2. Run your first example
python examples/basic/01_simple_analysis.py

# 3. Explore the results!
```

---

## 🆘 Troubleshooting

### Import errors
```bash
# Make sure you're in the project root
cd /path/to/reveng-main

# Reinstall
pip install -e . --force-reinstall

# Try again
python examples/basic/01_simple_analysis.py
```

### File not found
```bash
# Specify full path
python examples/basic/01_simple_analysis.py /full/path/to/binary

# Or use a system binary
python examples/basic/01_simple_analysis.py /bin/ls  # Linux/macOS
```

---

## 📖 Next Steps

After completing these basic examples:

1. **Try intermediate examples:**
   ```bash
   python examples/javascript_deobfuscation_demo.py
   ```

2. **Try advanced examples:**
   ```bash
   python examples/advanced/v4_0_features_demo.py
   ```

3. **Read the full documentation:**
   - [QUICK_START.md](../../QUICK_START.md)
   - [CLI_REFERENCE.md](../../CLI_REFERENCE.md)
   - [docs/](../../docs/)

---

## 🤝 Contributing

Found an issue or want to add more examples?

1. Open an issue: https://github.com/oimiragieo/reveng-main/issues
2. Submit a PR with your example
3. Follow the [CONTRIBUTING.md](../../CONTRIBUTING.md) guidelines

---

**Happy learning!** 🎓
