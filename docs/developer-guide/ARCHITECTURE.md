# REVENG Architecture

This document describes the system architecture of the REVENG Universal Reverse Engineering Platform.

## 🏗️ System Overview

REVENG is designed as a modular, extensible platform with the following key components:

```
┌─────────────────────────────────────────────────────────────┐
│                    REVENG Platform                          │
├─────────────────────────────────────────────────────────────┤
│  Web Interface (React)  │  CLI Interface  │  Python API    │
├─────────────────────────────────────────────────────────────┤
│                    Core Analysis Engine                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│  │   AI/ML     │ │  Language   │ │  Binary     │ │  Code   │ │
│  │  Analysis   │ │  Detection  │ │  Analysis   │ │  Gen    │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Tool Ecosystem                           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│  │   Ghidra    │ │   LIEF      │ │  Keystone   │ │  Other  │ │
│  │ Integration │ │  Binary     │ │  Assembler  │ │  Tools  │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Data Layer                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│  │   Models    │ │  Datasets   │ │  Config     │ │  Cache  │ │
│  │   (ML)      │ │  (Training) │ │  (Settings) │ │  (Temp) │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Core Components

### 1. Main Analysis Pipeline (`reveng_analyzer.py`)

The central orchestrator that coordinates the 8-step analysis process:

```python
class REVENGAnalyzer:
    def analyze_binary(self):
        # Step 1: AI-powered binary analysis
        self._step1_ai_analysis()
        
        # Step 2: Complete disassembly
        self._step2_disassembly()
        
        # Step 3: AI inspection with extra thinking
        self._step3_ai_inspection()
        
        # Step 4: Specification library creation
        self._step4_specifications()
        
        # Step 5: Human-readable code conversion
        self._step5_human_readable()
        
        # Step 6: Deobfuscation and domain splitting
        self._step6_deobfuscation()
        
        # Step 7: Implementation of missing features
        self._step7_implementation()
        
        # Step 8: Binary validation
        self._step8_validation()
```

### 2. Tool Ecosystem (`tools/`)

66+ specialized analysis tools organized by category:

#### Core Analysis Tools
- `ai_recompiler_converter.py` - AI-powered analysis
- `optimal_binary_analysis.py` - Ghidra integration
- `language_detector.py` - Multi-language detection

#### Binary Processing Tools
- `binary_reassembler_v2.py` - Binary reconstruction
- `human_readable_converter_fixed.py` - Code generation
- `code_formatter.py` - Code formatting

#### AI/ML Tools
- `ai_analyzer_enhanced.py` - Enhanced AI analysis
- `ml_malware_classifier.py` - Malware classification
- `vulnerability_discovery_engine.py` - Vulnerability detection

#### Enterprise Tools
- `audit_trail.py` - Audit logging
- `plugin_system.py` - Plugin architecture
- `gpu_accelerator.py` - GPU acceleration

### 3. Language-Specific Analyzers

#### Java Analysis
```python
class JavaBytecodeAnalyzer:
    def analyze(self, binary_path):
        # Decompile Java bytecode
        # Detect obfuscation
        # Generate clean source
```

#### C# Analysis
```python
class CSharpILAnalyzer:
    def analyze(self, binary_path):
        # Analyze .NET IL
        # Detect obfuscation
        # Generate C# source
```

#### Python Analysis
```python
class PythonBytecodeAnalyzer:
    def analyze(self, binary_path):
        # Decompile Python bytecode
        # Detect obfuscation
        # Generate Python source
```

#### Native Binary Analysis
```python
class NativeBinaryAnalyzer:
    def analyze(self, binary_path):
        # Use Ghidra for disassembly
        # Generate C source
        # Detect vulnerabilities
```

## 🔄 Data Flow

### Analysis Pipeline Flow

```
Binary Input
    ↓
Language Detection
    ↓
┌─────────────────┬─────────────────┬─────────────────┐
│   Java Path     │   C# Path       │   Native Path    │
│                 │                 │                 │
│ Java Analyzer   │ C# Analyzer     │ Ghidra Analysis │
│ ↓               │ ↓               │ ↓               │
│ Decompilation   │ IL Analysis     │ Disassembly     │
│ ↓               │ ↓               │ ↓               │
│ Source Gen      │ Source Gen      │ Source Gen      │
└─────────────────┴─────────────────┴─────────────────┘
    ↓
Code Processing
    ↓
┌─────────────────┬─────────────────┬─────────────────┐
│   Formatting    │   Deobfuscation │   Validation     │
│                 │                 │                 │
│ Code Formatter  │ Deobfuscator    │ Binary Validator│
└─────────────────┴─────────────────┴─────────────────┘
    ↓
Output Generation
    ↓
┌─────────────────┬─────────────────┬─────────────────┐
│   Source Code   │   Reports       │   Documentation │
│                 │                 │                 │
│ Clean C/Java   │ JSON Reports    │ API Docs        │
│ Source Files    │ Analysis Data   │ User Guides     │
└─────────────────┴─────────────────┴─────────────────┘
```

## 🧩 Modular Architecture

### Plugin System

REVENG supports a plugin architecture for extensibility:

```python
class PluginManager:
    def load_plugin(self, plugin_path):
        # Load custom analyzer
        # Register with main pipeline
        # Add to tool ecosystem
```

### Tool Categories

Tools are organized by functionality in `tools/categories.json`:

```json
{
  "core_analysis": [
    "ai_recompiler_converter.py",
    "optimal_binary_analysis.py",
    "language_detector.py"
  ],
  "binary_processing": [
    "binary_reassembler_v2.py",
    "human_readable_converter_fixed.py",
    "code_formatter.py"
  ],
  "ai_ml": [
    "ai_analyzer_enhanced.py",
    "ml_malware_classifier.py",
    "vulnerability_discovery_engine.py"
  ]
}
```

## 🌐 Web Interface Architecture

### Frontend (React)
```
src/
├── components/
│   ├── Analysis/
│   │   ├── ProgressTracker.js
│   │   └── ResultsVisualization.js
│   ├── Auth/
│   │   └── ProtectedRoute.js
│   └── Layout/
│       └── Layout.js
├── pages/
│   ├── Dashboard/
│   ├── Analysis/
│   ├── Projects/
│   └── Admin/
└── contexts/
    ├── AuthContext.js
    └── SocketContext.js
```

### Backend (Node.js)
```
server/
├── routes/
│   ├── analysis.js
│   ├── auth.js
│   ├── projects.js
│   └── admin.js
├── services/
│   ├── analysisService.js
│   ├── aiService.py
│   └── websocketService.js
└── middleware/
    ├── auth.js
    └── errorHandler.js
```

### Docker Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Compose                           │
├─────────────────────────────────────────────────────────────┤
│  Frontend (React)  │  Backend (Node.js)  │  AI Service     │
│  Port: 3000        │  Port: 5000         │  Port: 8000     │
├─────────────────────────────────────────────────────────────┤
│  Worker (Python)   │  Database (Redis)   │  Storage        │
│  Background Jobs   │  Session Store      │  File Storage   │
└─────────────────────────────────────────────────────────────┘
```

## 🔒 Security Architecture

### Security Layers

1. **Input Validation**
   - File type verification
   - Size limits
   - Malware scanning

2. **Sandboxing**
   - Isolated execution environments
   - Resource limits
   - Network restrictions

3. **Audit Logging**
   - User actions
   - System events
   - Security incidents

4. **Access Control**
   - Authentication
   - Authorization
   - Role-based permissions

## 📊 Performance Architecture

### Scalability Design

1. **Horizontal Scaling**
   - Multiple worker processes
   - Load balancing
   - Distributed processing

2. **Caching Strategy**
   - Analysis result caching
   - Model caching
   - Session caching

3. **Resource Management**
   - Memory limits
   - CPU throttling
   - Disk space management

### Performance Optimization

1. **Parallel Processing**
   - Multi-threaded analysis
   - Async operations
   - Batch processing

2. **GPU Acceleration**
   - CUDA support
   - OpenCL support
   - ML model acceleration

3. **Memory Management**
   - Streaming processing
   - Garbage collection
   - Memory pooling

## 🔧 Configuration Architecture

### Configuration Hierarchy

```
1. Environment Variables
2. .env files
3. config.yaml
4. Command line arguments
5. Default values
```

### Configuration Management

```python
class ConfigManager:
    def __init__(self):
        self.config = self.load_config()
        self.validate_config()
        self.apply_config()
```

## 📈 Monitoring Architecture

### Health Monitoring

1. **System Health**
   - CPU usage
   - Memory usage
   - Disk space
   - Network status

2. **Application Health**
   - Service status
   - Response times
   - Error rates
   - Queue lengths

3. **Business Metrics**
   - Analysis success rate
   - Processing time
   - User activity
   - Feature usage

### Logging Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Logging System                           │
├─────────────────────────────────────────────────────────────┤
│  Application Logs  │  Audit Logs  │  Error Logs  │  Metrics │
│  (Info/Debug)      │  (Security)  │  (Errors)    │  (Stats) │
├─────────────────────────────────────────────────────────────┤
│  Local Storage     │  Remote Storage  │  Real-time Monitor  │
│  (Files)           │  (ELK Stack)     │  (Dashboards)       │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Deployment Architecture

### Development Environment
```
Developer Machine
├── Python 3.11+
├── Git Repository
├── Local Dependencies
└── Development Tools
```

### Production Environment
```
Production Server
├── Docker Containers
├── Kubernetes Cluster
├── Load Balancer
├── Database
└── Monitoring
```

### Cloud Deployment
```
Cloud Infrastructure
├── Container Registry
├── Orchestration (K8s)
├── Auto-scaling
├── Load Balancing
└── Monitoring & Logging
```

## 🔄 Extension Points

### Custom Analyzers

```python
class CustomAnalyzer:
    def analyze(self, binary_path):
        # Custom analysis logic
        return analysis_results
    
    def register(self):
        # Register with main pipeline
        pass
```

### Custom Tools

```python
class CustomTool:
    def __init__(self):
        self.name = "Custom Tool"
        self.category = "custom"
    
    def execute(self, input_data):
        # Tool implementation
        return output_data
```

### Custom Plugins

```python
class CustomPlugin:
    def __init__(self):
        self.name = "Custom Plugin"
        self.version = "1.0.0"
    
    def install(self):
        # Plugin installation
        pass
    
    def uninstall(self):
        # Plugin removal
        pass
```

## 📚 API Architecture

### REST API Design

```
/api/v1/
├── /analysis/
│   ├── POST /start
│   ├── GET /status/{id}
│   └── GET /results/{id}
├── /projects/
│   ├── GET /
│   ├── POST /
│   └── DELETE /{id}
└── /admin/
    ├── GET /health
    └── GET /metrics
```

### WebSocket API

```
/ws/
├── /analysis/progress
├── /analysis/status
└── /system/events
```

## 🔧 Development Architecture

### Code Organization

```
reveng-main/
├── reveng_analyzer.py          # Main entry point
├── tools/                       # Analysis tools
├── tests/                       # Test suite
├── docs/                        # Documentation
├── examples/                    # Usage examples
├── web_interface/               # Web UI
├── scripts/                     # Utility scripts
└── models/                      # ML models
```

### Testing Architecture

```
tests/
├── unit/                        # Unit tests
├── integration/                 # Integration tests
├── e2e/                         # End-to-end tests
├── performance/                 # Performance tests
└── security/                    # Security tests
```

---

**Architecture Summary**

REVENG is designed as a modular, extensible platform with:
- **8-step analysis pipeline** for comprehensive binary analysis
- **66+ specialized tools** for different analysis tasks
- **Multi-language support** for Java, C#, Python, and native binaries
- **AI/ML integration** for intelligent analysis
- **Web interface** for user-friendly access
- **Plugin system** for extensibility
- **Enterprise features** for production use

The architecture supports both standalone CLI usage and enterprise deployment with web interfaces, making it suitable for individual researchers and large organizations alike.
