# REVENG ML Models

## Overview

Pre-trained machine learning models for binary analysis including malware classification, function identification, and code similarity.

**Location:** `/home/user/reveng-main/src/reveng/ml_models/`

## Key Features

### Classification Models
- Malware classifier
- Compiler detector
- Architecture classifier
- Packer detector

### Analysis Models
- Function purpose predictor
- Variable name suggester
- Code similarity
- Pattern recognition

### Model Management
- Model versioning
- Model updates
- Model optimization
- Inference optimization

## Usage Examples

### Example 1: Malware Classification

```python
from reveng.ml_models import MalwareClassifier

classifier = MalwareClassifier()
result = classifier.classify("/path/to/binary.exe")

print(f"Is malicious: {result['is_malicious']}")
print(f"Family: {result['family']}")
print(f"Confidence: {result['confidence']}")
```

### Example 2: Function Naming

```python
from reveng.ml_models import FunctionNamer

namer = FunctionNamer()
suggested_name = namer.suggest_name(
    function_code="...",
    context={...}
)

print(f"Suggested name: {suggested_name}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/ml/` - ML utilities
- `/home/user/reveng-main/src/reveng/ai/` - AI features

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
