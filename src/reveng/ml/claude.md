# Directory: src/reveng/ml

## Overview
This directory contains machine learning integration for REVENG, providing ML-powered code reconstruction, anomaly detection, and intelligent analysis capabilities.

## Files in This Directory

### __init__.py
- **Purpose**: Package initialization, exports MLIntegration and MLIntegrationConfig
- **Key Classes**: `MLIntegration`, `MLIntegrationConfig`
- **Dependencies**: `.integration`
- **Used By**: Main analyzer, API

### integration.py
- **Purpose**: Main ML integration interface
- **Key Classes**:
  - `MLIntegration`: Primary ML interface for binary analysis
  - `MLIntegrationConfig`: ML configuration dataclass
- **Key Functions**:
  - `analyze_binary()`: ML-enhanced binary analysis
  - `detect_threats()`: ML-based threat detection
  - `reconstruct_code()`: ML-powered code reconstruction
  - `predict_vulnerabilities()`: ML vulnerability prediction
  - `classify_binary()`: Binary classification using ML
- **Dependencies**: ML models, `.code_reconstruction`, `.anomaly_detection`
- **Used By**: Analyzer, API

### code_reconstruction.py
- **Purpose**: ML-based code reconstruction from binaries
- **Key Classes**: `CodeReconstructor`
- **Key Functions**:
  - `reconstruct()`: Reconstruct source code from binary
  - `improve_decompilation()`: Enhance decompiled code quality
  - `generate_build_system()`: Create build files
- **Dependencies**: ML models (transformer-based)
- **Used By**: Binary reconstruction pipeline

### anomaly_detection.py
- **Purpose**: ML-based anomaly detection in binaries
- **Key Classes**: `AnomalyDetector`
- **Key Functions**:
  - `detect_anomalies()`: Find unusual patterns
  - `score_anomalies()`: Score anomaly severity
  - `classify_anomalies()`: Categorize anomalies
- **Dependencies**: ML models (isolation forest, autoencoders)
- **Used By**: Malware detection, quality analysis

## Architecture

```
┌─────────────────────────────────────┐
│   ML Integration Layer              │
├─────────────────────────────────────┤
│ • Code Reconstruction               │
│ • Anomaly Detection                 │
│ • Threat Classification             │
│ • Vulnerability Prediction          │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────────────┐
       │   ML Models            │
       ├────────────────────────┤
       │ • Transformers         │
       │ • Random Forests       │
       │ • Neural Networks      │
       │ • Autoencoders         │
       └────────────────────────┘
```

## Key Concepts

### ML-Powered Analysis
- **Code Reconstruction**: Transform decompiled code to readable source
- **Anomaly Detection**: Find unusual patterns indicating malware or bugs
- **Classification**: Categorize binaries by type, purpose, threat level
- **Prediction**: Predict vulnerabilities before they're exploited

### Model Types
- **Transformers**: Code understanding and generation
- **Random Forests**: Binary classification
- **Neural Networks**: Pattern recognition
- **Autoencoders**: Anomaly detection

## Usage Examples

### ML Integration
```python
from reveng.ml import MLIntegration

ml = MLIntegration()

# Analyze binary with ML
results = ml.analyze_binary("app.exe", ghidra_data)
print(f"Confidence: {results.get('confidence')}")
print(f"Classification: {results.get('classification')}")

# Detect threats
threats = ml.detect_threats("malware.exe")
print(f"Is malware: {threats['is_malware']}")
print(f"Threat level: {threats['threat_level']}")
```

### Code Reconstruction
```python
from reveng.ml.code_reconstruction import CodeReconstructor

reconstructor = CodeReconstructor()

# Reconstruct code
result = reconstructor.reconstruct(
    decompiled_code="<decompiled C code>",
    target_language="python"
)

print(f"Reconstructed code:\n{result.source_code}")
print(f"Quality score: {result.quality_score}")
```

### Anomaly Detection
```python
from reveng.ml.anomaly_detection import AnomalyDetector

detector = AnomalyDetector()

# Detect anomalies
anomalies = detector.detect_anomalies("suspicious.exe")

for anomaly in anomalies:
    print(f"Type: {anomaly.type}")
    print(f"Severity: {anomaly.severity}")
    print(f"Location: {anomaly.location}")
```

## Configuration

### ML Model Configuration
```python
from reveng.ml import MLIntegrationConfig

config = MLIntegrationConfig(
    models_dir="/path/to/models",
    use_gpu=True,
    cache_predictions=True,
    batch_size=32
)

ml = MLIntegration(config=config)
```

## Testing

### Unit Tests
```bash
pytest tests/ml/test_integration.py
pytest tests/ml/test_code_reconstruction.py
pytest tests/ml/test_anomaly_detection.py
```

## Related Modules

### Dependencies
- `src/reveng/security/`: ML security modules
- ML libraries (transformers, scikit-learn, pytorch)

### Used By
- `src/reveng/analyzer.py`: Uses ML for enhanced analysis
- `src/reveng/api.py`: Exposes ML capabilities

## Notes

### Model Requirements
- Models require significant disk space (1-10GB)
- GPU recommended for inference
- First run downloads models

### Performance
- ML inference adds 1-5 minutes to analysis
- GPU significantly faster than CPU
- Model loading is one-time cost

### Best Practices
1. Use GPU for faster inference
2. Cache model predictions
3. Batch multiple binaries when possible
4. Update models regularly
5. Validate ML outputs manually
