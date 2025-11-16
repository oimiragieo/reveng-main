# Plugins - AI

## Overview

AI plugins enhance REVENG analysis with artificial intelligence and machine learning capabilities, including code reconstruction, intelligent naming, and AI-powered analysis enhancement.

**Location:** `/home/user/reveng-main/src/reveng/plugins/ai/`

## Files in This Directory

### `code_reconstruction_plugin.py` (18790 lines)
AI-powered code reconstruction and analysis enhancement plugin.

**CodeReconstructionPlugin:**
- **Category:** AI_ENHANCEMENT
- **Priority:** HIGH
- **Dependencies:** `openai`, `anthropic`, `transformers`

**Features:**
1. **Code Reconstruction** - Rebuild high-level code from assembly
2. **Intelligent Renaming** - AI-powered variable/function naming
3. **Comment Generation** - Automatic code documentation
4. **Type Inference** - Infer variable types from usage
5. **Pattern Recognition** - Identify common code patterns
6. **Decompilation Enhancement** - Improve decompiler output

**AI Models Used:**
- CodeBERT - Code understanding
- CodeT5 - Code generation
- GPT-4 / Claude - Advanced reasoning
- Custom trained models - Domain-specific tasks

**Usage:**
```python
from reveng.plugins.ai import CodeReconstructionPlugin

plugin = CodeReconstructionPlugin()
result = plugin.ai_enhance(context, decompiled_code)

print(f"Reconstructed Code:\n{result['reconstructed_code']}")
print(f"Confidence: {result['confidence']}")
```

## Architecture

### AI Enhancement Pipeline

```
Decompiled Code
  ↓
Code Normalization
  ↓
AI Model Selection
  ├─> CodeBERT (understanding)
  ├─> CodeT5 (generation)
  └─> GPT-4/Claude (reasoning)
  ↓
Enhancement Stages
  ├─> Variable renaming
  ├─> Type inference
  ├─> Comment generation
  └─> Code restructuring
  ↓
Enhanced Code Output
```

### Model Integration

```
CodeReconstructionPlugin
  ├─> Local Models
  │   ├─> CodeBERT
  │   ├─> CodeT5
  │   └─> CodeGen
  │
  └─> API Models
      ├─> OpenAI GPT-4
      └─> Anthropic Claude
```

## Key Concepts

### 1. Multi-Model Approach

Combines multiple AI models for best results:

```python
# Local model for fast tasks
local_result = codebert_model.encode(code)

# API model for complex tasks
api_result = gpt4_model.complete(prompt)

# Combine results
final_output = combine_results(local_result, api_result)
```

### 2. Confidence Scoring

All AI outputs include confidence scores:

```python
result = {
    "reconstructed_code": "...",
    "confidence": 0.87,  # 0.0 - 1.0
    "method": "gpt4",
    "fallback_used": False
}
```

### 3. Incremental Enhancement

Code is enhanced in stages:

1. Variable renaming (fast, high confidence)
2. Type inference (medium speed, medium confidence)
3. Comment generation (slow, variable confidence)
4. Full reconstruction (slowest, requires review)

## Usage Examples

### Example 1: Basic Code Reconstruction

```python
from reveng.plugins.ai import CodeReconstructionPlugin
from reveng.plugins.base import PluginContext

plugin = CodeReconstructionPlugin()
context = PluginContext(binary_path="app.exe")

if plugin.initialize(context):
    # Get decompiled code
    decompiled = context.get_decompiled_code()

    # Apply AI enhancement
    result = plugin.ai_enhance(context, decompiled)

    print(f"Original:\n{decompiled['code'][:200]}")
    print(f"\nEnhanced:\n{result['reconstructed_code'][:200]}")
    print(f"\nConfidence: {result['confidence'] * 100}%")
```

### Example 2: Intelligent Variable Renaming

```python
result = plugin.ai_enhance(context, {
    "code": decompiled_code,
    "enhancement_type": "rename_variables"
})

# View renamed variables
for old_name, new_name in result['renamings'].items():
    print(f"{old_name} → {new_name}")
```

### Example 3: Type Inference

```python
result = plugin.ai_enhance(context, {
    "code": decompiled_code,
    "enhancement_type": "infer_types"
})

# View inferred types
for var_name, var_type in result['type_annotations'].items():
    print(f"{var_name}: {var_type}")
```

### Example 4: Full Enhancement Pipeline

```python
# Configure full enhancement
context.options = {
    "rename_variables": True,
    "infer_types": True,
    "generate_comments": True,
    "restructure_code": True,
    "use_api_models": True,
    "confidence_threshold": 0.7
}

result = plugin.ai_enhance(context, decompiled_code)

# Save enhanced code
with open("enhanced_output.c", "w") as f:
    f.write(result['reconstructed_code'])
```

## Configuration

### API Configuration

```python
import os

# Set API keys
os.environ["OPENAI_API_KEY"] = "your-key"
os.environ["ANTHROPIC_API_KEY"] = "your-key"

# Configure plugin
context.options = {
    "preferred_model": "gpt-4",  # or "claude"
    "fallback_model": "gpt-3.5-turbo",
    "use_local_models": True,
    "max_tokens": 4000,
    "temperature": 0.3
}
```

### Model Selection

```python
context.options = {
    "model_preferences": {
        "variable_renaming": "codebert",  # Fast local model
        "type_inference": "codet5",       # Medium complexity
        "full_reconstruction": "gpt-4"    # Complex reasoning
    }
}
```

## Testing

### Unit Tests

```python
import pytest
from reveng.plugins.ai import CodeReconstructionPlugin

@pytest.mark.asyncio
async def test_code_reconstruction():
    plugin = CodeReconstructionPlugin()
    context = PluginContext()

    result = plugin.ai_enhance(context, {
        "code": "void func_1(int var_0) { ... }",
        "enhancement_type": "rename_variables"
    })

    assert result['confidence'] > 0.5
    assert 'reconstructed_code' in result
    assert 'var_0' not in result['reconstructed_code']
```

### Performance Tests

```bash
# Benchmark AI models
pytest tests/plugins/ai/test_performance.py --benchmark

# Test with different models
pytest tests/plugins/ai/ --model=gpt-4
pytest tests/plugins/ai/ --model=claude
pytest tests/plugins/ai/ --model=codebert
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/plugins/` - Plugin framework
- `/home/user/reveng-main/src/reveng/ai/` - AI/ML utilities
- `/home/user/reveng-main/src/reveng/ml_models/` - Pre-trained models

### External Dependencies
- `openai` - OpenAI API client
- `anthropic` - Anthropic API client
- `transformers` - HuggingFace models

## Notes

**Best Practices:**
1. Start with local models, fallback to API models
2. Use confidence thresholds to filter low-quality results
3. Review AI-generated code manually
4. Cache results to avoid redundant API calls
5. Monitor API usage and costs

**Limitations:**
- AI models can hallucinate or make mistakes
- Complex code may not be reconstructed accurately
- API models have cost and rate limits
- Local models require significant compute resources

**Future Enhancements:**
- [ ] Custom model fine-tuning
- [ ] Multi-language support
- [ ] Real-time code suggestions
- [ ] Interactive refinement
- [ ] Collaborative AI-human analysis

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
