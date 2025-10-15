# REVENG API Reference

This document provides comprehensive API documentation for the REVENG Universal Reverse Engineering Platform.

## 📚 Table of Contents

- [Core API](#core-api)
- [Tool APIs](#tool-apis)
- [Web Interface API](#web-interface-api)
- [Configuration API](#configuration-api)
- [Error Handling](#error-handling)
- [Examples](#examples)

## 🔧 Core API

### REVENGAnalyzer

The main analysis class that orchestrates the 8-step analysis pipeline.

```python
class REVENGAnalyzer:
    def __init__(self, binary_path: str = None, check_ollama: bool = True, 
                 enhanced_features: Optional[EnhancedAnalysisFeatures] = None)
    
    def analyze_binary(self) -> bool
    def _step1_ai_analysis(self) -> None
    def _step2_disassembly(self) -> None
    def _step3_ai_inspection(self) -> None
    def _step4_specifications(self) -> None
    def _step5_human_readable(self) -> None
    def _step6_deobfuscation(self) -> None
    def _step7_implementation(self) -> None
    def _step8_validation(self) -> None
```

#### Parameters

- `binary_path` (str, optional): Path to binary file to analyze
- `check_ollama` (bool): Whether to check Ollama availability (default: True)
- `enhanced_features` (EnhancedAnalysisFeatures, optional): Enhanced analysis configuration

#### Returns

- `bool`: True if analysis completed successfully, False otherwise

#### Example

```python
from reveng_analyzer import REVENGAnalyzer

# Basic usage
analyzer = REVENGAnalyzer("binary.exe")
success = analyzer.analyze_binary()

# With enhanced features
from reveng_analyzer import EnhancedAnalysisFeatures

features = EnhancedAnalysisFeatures()
features.enable_corporate_exposure = True
features.enable_vulnerability_discovery = True

analyzer = REVENGAnalyzer("binary.exe", enhanced_features=features)
success = analyzer.analyze_binary()
```

### EnhancedAnalysisFeatures

Configuration class for enhanced analysis features.

```python
class EnhancedAnalysisFeatures:
    def __init__(self):
        self.enable_enhanced_analysis = True
        self.enable_corporate_exposure = True
        self.enable_vulnerability_discovery = True
        self.enable_threat_intelligence = True
        self.enable_enhanced_reconstruction = True
        self.enable_demonstration_generation = True
    
    def from_config(self, config_dict: Dict[str, Any]) -> 'EnhancedAnalysisFeatures'
    def is_any_enhanced_enabled(self) -> bool
```

## 🛠️ Tool APIs

### Language Detection

```python
class LanguageDetector:
    def detect(self, file_path: str) -> LanguageResult
    def get_language_category(self, result: LanguageResult) -> str
```

#### LanguageResult

```python
@dataclass
class LanguageResult:
    language: str          # 'java', 'csharp', 'python', 'native'
    format: str           # 'jar', 'exe', 'pyc', 'pe', 'elf'
    confidence: float     # 0.0 to 1.0
```

#### Example

```python
from tools.language_detector import LanguageDetector

detector = LanguageDetector()
result = detector.detect("app.jar")
print(f"Language: {result.language}, Format: {result.format}, Confidence: {result.confidence}")
```

### AI Analysis

```python
class AIRecompilerConverter:
    def analyze(self, binary_path: str) -> Dict[str, Any]
    def get_analysis_results(self) -> Dict[str, Any]
```

#### Example

```python
from tools.ai_recompiler_converter import AIRecompilerConverter

ai_converter = AIRecompilerConverter()
results = ai_converter.analyze("binary.exe")
print(f"Analysis confidence: {results.get('confidence', 0)}")
```

### Binary Analysis

```python
class OptimalBinaryAnalysis:
    def analyze(self, binary_path: str) -> Dict[str, Any]
    def get_functions(self) -> List[Dict[str, Any]]
    def get_strings(self) -> List[str]
```

#### Example

```python
from tools.optimal_binary_analysis import OptimalBinaryAnalysis

analyzer = OptimalBinaryAnalysis()
results = analyzer.analyze("binary.exe")
functions = analyzer.get_functions()
print(f"Found {len(functions)} functions")
```

### Code Generation

```python
class HumanReadableConverter:
    def convert(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]
    def generate_source(self, function_data: Dict[str, Any]) -> str
```

#### Example

```python
from tools.human_readable_converter_fixed import HumanReadableConverter

converter = HumanReadableConverter()
source_code = converter.generate_source(function_data)
print(f"Generated {len(source_code)} lines of code")
```

### Binary Reassembly

```python
class BinaryReassembler:
    def reassemble(self, original_path: str, source_dir: str, 
                   output_path: str, arch: str = 'auto') -> bool
    def validate_rebuild(self, original_path: str, rebuilt_path: str) -> Dict[str, Any]
```

#### Example

```python
from tools.binary_reassembler_v2 import BinaryReassembler

reassembler = BinaryReassembler()
success = reassembler.reassemble(
    original_path="original.exe",
    source_dir="human_readable_code/",
    output_path="rebuilt.exe"
)
```

## 🌐 Web Interface API

### REST Endpoints

#### Analysis Endpoints

```http
POST /api/v1/analysis/start
Content-Type: application/json

{
  "binary_path": "path/to/binary.exe",
  "options": {
    "enhanced_analysis": true,
    "ai_enabled": true
  }
}
```

**Response:**
```json
{
  "analysis_id": "uuid-string",
  "status": "started",
  "estimated_time": 300
}
```

```http
GET /api/v1/analysis/status/{analysis_id}
```

**Response:**
```json
{
  "analysis_id": "uuid-string",
  "status": "running",
  "progress": 45,
  "current_step": "AI Analysis",
  "estimated_remaining": 180
}
```

```http
GET /api/v1/analysis/results/{analysis_id}
```

**Response:**
```json
{
  "analysis_id": "uuid-string",
  "status": "completed",
  "results": {
    "source_code": "path/to/source/",
    "reports": "path/to/reports/",
    "validation": "path/to/validation/"
  },
  "summary": {
    "functions_analyzed": 150,
    "vulnerabilities_found": 3,
    "confidence_score": 0.95
  }
}
```

#### Project Endpoints

```http
GET /api/v1/projects/
```

**Response:**
```json
[
  {
    "id": "uuid-string",
    "name": "Project Name",
    "created_at": "2025-01-13T10:00:00Z",
    "status": "completed",
    "binary_count": 5
  }
]
```

```http
POST /api/v1/projects/
Content-Type: application/json

{
  "name": "New Project",
  "description": "Project description"
}
```

### WebSocket Events

#### Analysis Progress

```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:5000/ws/analysis/progress');

// Listen for progress updates
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log(`Progress: ${data.progress}%`);
  console.log(`Current step: ${data.current_step}`);
};
```

#### System Events

```javascript
// Connect to system events
const ws = new WebSocket('ws://localhost:5000/ws/system/events');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log(`System event: ${data.type}`);
  console.log(`Message: ${data.message}`);
};
```

## ⚙️ Configuration API

### ConfigManager

```python
class ConfigManager:
    def __init__(self, config_path: str = ".reveng/config.yaml")
    def load_config(self) -> Dict[str, Any]
    def save_config(self, config: Dict[str, Any]) -> None
    def get_ai_config(self) -> AIConfig
    def get_analysis_config(self) -> AnalysisConfig
```

#### AIConfig

```python
@dataclass
class AIConfig:
    enable_ai: bool = True
    provider: str = 'ollama'  # 'ollama', 'anthropic', 'openai'
    ollama_host: str = 'http://localhost:11434'
    ollama_model: str = 'auto'
    anthropic_api_key: str = ''
    openai_api_key: str = ''
```

#### AnalysisConfig

```python
@dataclass
class AnalysisConfig:
    timeout: int = 300
    max_functions: int = 100
    enable_enhanced_analysis: bool = True
    enable_corporate_exposure: bool = True
    enable_vulnerability_discovery: bool = True
```

#### Example

```python
from tools.config_manager import ConfigManager

config_manager = ConfigManager()
config = config_manager.load_config()

# Update AI configuration
ai_config = config_manager.get_ai_config()
ai_config.provider = 'anthropic'
ai_config.anthropic_api_key = 'your-api-key'
config_manager.save_config(config)
```

## 🚨 Error Handling

### Exception Hierarchy

```python
class REVENGException(Exception):
    """Base exception for REVENG"""

class AnalysisError(REVENGException):
    """Analysis-specific errors"""

class ToolError(REVENGException):
    """Tool execution errors"""

class ConfigurationError(REVENGException):
    """Configuration-related errors"""

class ValidationError(REVENGException):
    """Validation errors"""
```

### Error Codes

```python
class ErrorCodes:
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    CONFIGURATION_INVALID = "CONFIGURATION_INVALID"
    BINARY_NOT_FOUND = "BINARY_NOT_FOUND"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    TIMEOUT = "TIMEOUT"
    MEMORY_ERROR = "MEMORY_ERROR"
```

### Error Response Format

```json
{
  "error": {
    "code": "ANALYSIS_FAILED",
    "message": "Analysis failed due to invalid binary format",
    "details": {
      "step": "language_detection",
      "binary_path": "invalid.exe",
      "timestamp": "2025-01-13T10:00:00Z"
    }
  }
}
```

## 📊 Return Types

### Analysis Results

```python
@dataclass
class AnalysisResults:
    binary_path: str
    binary_name: str
    analysis_folder: str
    success: bool
    steps_completed: int
    total_steps: int
    results: Dict[str, Any]
    enhanced_results: Dict[str, Any]
    summary: Dict[str, Any]
```

### Function Data

```python
@dataclass
class FunctionData:
    name: str
    address: str
    size: int
    complexity: str
    source_code: str
    assembly_code: str
    callers: List[str]
    callees: List[str]
```

### Vulnerability Data

```python
@dataclass
class VulnerabilityData:
    type: str
    severity: str
    confidence: float
    location: str
    description: str
    remediation: str
```

## 🔧 Examples

### Basic Analysis

```python
from reveng_analyzer import REVENGAnalyzer

# Analyze a binary
analyzer = REVENGAnalyzer("app.exe")
success = analyzer.analyze_binary()

if success:
    print("Analysis completed successfully!")
    print(f"Results saved to: {analyzer.analysis_folder}")
else:
    print("Analysis failed!")
```

### Custom Analysis Pipeline

```python
from tools.language_detector import LanguageDetector
from tools.ai_recompiler_converter import AIRecompilerConverter
from tools.human_readable_converter_fixed import HumanReadableConverter

# Step 1: Detect language
detector = LanguageDetector()
language_result = detector.detect("app.jar")

# Step 2: AI analysis
ai_converter = AIRecompilerConverter()
ai_results = ai_converter.analyze("app.jar")

# Step 3: Generate source code
converter = HumanReadableConverter()
source_code = converter.convert(ai_results)
```

### Web API Usage

```python
import requests

# Start analysis
response = requests.post('http://localhost:5000/api/v1/analysis/start', json={
    'binary_path': 'app.exe',
    'options': {
        'enhanced_analysis': True,
        'ai_enabled': True
    }
})

analysis_id = response.json()['analysis_id']

# Check status
status_response = requests.get(f'http://localhost:5000/api/v1/analysis/status/{analysis_id}')
print(f"Status: {status_response.json()['status']}")

# Get results
results_response = requests.get(f'http://localhost:5000/api/v1/analysis/results/{analysis_id}')
results = results_response.json()
print(f"Analysis completed: {results['summary']}")
```

### Configuration Management

```python
from tools.config_manager import ConfigManager

# Load configuration
config_manager = ConfigManager()
config = config_manager.load_config()

# Update settings
config['ai']['provider'] = 'anthropic'
config['ai']['anthropic_api_key'] = 'your-api-key'
config['analysis']['timeout'] = 600

# Save configuration
config_manager.save_config(config)
```

### Error Handling

```python
from reveng_analyzer import REVENGAnalyzer, AnalysisError

try:
    analyzer = REVENGAnalyzer("invalid.exe")
    success = analyzer.analyze_binary()
except AnalysisError as e:
    print(f"Analysis failed: {e}")
except FileNotFoundError:
    print("Binary file not found")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## 📚 Additional Resources

- **[User Guide](docs/USER_GUIDE.md)** - Complete usage documentation
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)** - Development workflows
- **[Architecture](ARCHITECTURE.md)** - System architecture
- **[Examples](examples/README.md)** - Usage examples
- **[GitHub Repository](https://github.com/oimiragieo/reveng-main)** - Source code

---

**API Reference Summary**

The REVENG API provides:
- **Core analysis pipeline** with 8-step process
- **66+ specialized tools** for different analysis tasks
- **REST API** for web interface integration
- **WebSocket API** for real-time updates
- **Configuration management** for customization
- **Comprehensive error handling** with detailed error codes
- **Type-safe interfaces** with dataclasses and type hints

The API is designed to be both powerful for advanced users and accessible for beginners, with comprehensive documentation and examples for all use cases.
