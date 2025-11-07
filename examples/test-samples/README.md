# Test Samples for JavaScript Deobfuscation

This directory contains sample obfuscated JavaScript files for testing the deobfuscation tools.

## Files

### 1. `obfuscated-simple.js`
**Type:** Minified
**Difficulty:** Easy
**Expected output:** Clean, formatted JavaScript with single-letter variable names

```bash
./reveng-js deobfuscate examples/test-samples/obfuscated-simple.js
```

### 2. `obfuscated-strings.js`
**Type:** String array obfuscation
**Difficulty:** Medium
**Expected output:** Strings decoded and inlined

```bash
./reveng-js deobfuscate examples/test-samples/obfuscated-strings.js --ml
```

### 3. `obfuscated-eval.js`
**Type:** Eval-based packing
**Difficulty:** Medium
**Expected output:** Unpacked and deobfuscated code

```bash
./reveng-js deobfuscate examples/test-samples/obfuscated-eval.js
```

## Usage

### Quick Test
```bash
# Test basic deobfuscation
./reveng-js deobfuscate examples/test-samples/obfuscated-simple.js

# Test with ML
./reveng-js deobfuscate examples/test-samples/obfuscated-strings.js --ml

# Test detection
./reveng-js detect examples/test-samples/obfuscated-eval.js
```

### Save Output
```bash
# Save to file
./reveng-js deobfuscate examples/test-samples/obfuscated-simple.js -o clean.js

# JSON format
./reveng-js deobfuscate examples/test-samples/obfuscated-simple.js -o result.json --format json
```

## Creating Your Own Samples

To test with your own obfuscated code:

1. Save your obfuscated JS to a file
2. Run the deobfuscation tool
3. Compare the output

```bash
./reveng-js deobfuscate your-file.js -o output.js -v
```
