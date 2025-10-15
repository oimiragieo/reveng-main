# Advanced Examples

This directory contains advanced examples demonstrating REVENG's powerful features.

## 📁 Examples

### 01_custom_analyzer.py
**Purpose**: Create custom analyzers

**Features**:
- Custom analysis logic
- Plugin architecture
- Extensible framework

**Usage**:
```bash
python examples/advanced/01_custom_analyzer.py --analyzer my_analyzer
```

### 02_plugin_development.py
**Purpose**: Develop REVENG plugins

**Features**:
- Plugin system
- Custom tools
- Integration examples

**Usage**:
```bash
python examples/advanced/02_plugin_development.py --plugin my_plugin
```

### 03_batch_processing.py
**Purpose**: Process multiple files

**Features**:
- Batch analysis
- Parallel processing
- Progress tracking

**Usage**:
```bash
python examples/advanced/03_batch_processing.py /path/to/binaries/
```

### 04_ai_integration.py
**Purpose**: AI service integration

**Features**:
- Ollama integration
- Anthropic API
- OpenAI integration

**Usage**:
```bash
python examples/advanced/04_ai_integration.py --ai-provider ollama
```

### 05_enterprise_features.py
**Purpose**: Enterprise features

**Features**:
- Corporate exposure analysis
- Vulnerability discovery
- Threat intelligence
- Audit logging

**Usage**:
```bash
python examples/advanced/05_enterprise_features.py --enterprise
```

## 🚀 Quick Start

1. **Prerequisites**: Complete basic examples first
2. **Configuration**: Set up AI services if needed
3. **Run examples**: Start with `01_custom_analyzer.py`

## 🔧 Customization

### Custom Analyzers

```python
# examples/advanced/custom_analyzer.py
from reveng_analyzer import REVENGAnalyzer
from tools.custom_analyzer import CustomAnalyzer

class MyCustomAnalyzer(CustomAnalyzer):
    def __init__(self, binary_path):
        super().__init__(binary_path)
        self.custom_config = {
            'timeout': 600,
            'max_functions': 1000,
            'enable_ai': True
        }
    
    def custom_analysis(self):
        """Custom analysis logic"""
        # Your custom analysis here
        pass
    
    def generate_report(self):
        """Generate custom report"""
        # Your custom reporting here
        pass

# Usage
analyzer = MyCustomAnalyzer("binary.exe")
analyzer.run_analysis()
```

### Plugin Development

```python
# examples/advanced/my_plugin.py
from tools.plugin_system import Plugin

class MyPlugin(Plugin):
    def __init__(self):
        super().__init__()
        self.name = "My Plugin"
        self.version = "1.0.0"
    
    def analyze(self, binary_path):
        """Plugin analysis logic"""
        # Your plugin logic here
        pass
    
    def install(self):
        """Plugin installation"""
        # Installation logic
        pass
    
    def uninstall(self):
        """Plugin removal"""
        # Cleanup logic
        pass
```

### Batch Processing

```python
# examples/advanced/batch_processor.py
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from reveng_analyzer import REVENGAnalyzer

class BatchProcessor:
    def __init__(self, input_dir, output_dir):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def process_binary(self, binary_path):
        """Process single binary"""
        try:
            analyzer = REVENGAnalyzer(str(binary_path))
            success = analyzer.analyze_binary()
            
            if success:
                # Move results to output directory
                results_dir = self.output_dir / binary_path.stem
                analyzer.move_results_to(str(results_dir))
                return f"✅ {binary_path.name}"
            else:
                return f"❌ {binary_path.name}"
        except Exception as e:
            return f"❌ {binary_path.name}: {e}"
    
    def process_all(self, max_workers=4):
        """Process all binaries in parallel"""
        binary_files = list(self.input_dir.glob("*.exe")) + \
                      list(self.input_dir.glob("*.jar")) + \
                      list(self.input_dir.glob("*.dll"))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(self.process_binary, binary_files))
        
        return results

# Usage
processor = BatchProcessor("input/", "output/")
results = processor.process_all()
for result in results:
    print(result)
```

## 🧪 Testing

### Run All Advanced Examples

```bash
# Run all advanced examples
python scripts/run_examples.py --advanced

# Run specific example
python examples/advanced/01_custom_analyzer.py --help
```

### Test Custom Features

```bash
# Test custom analyzer
python examples/advanced/01_custom_analyzer.py --test

# Test batch processing
python examples/advanced/03_batch_processing.py --test-dir test_samples/

# Test AI integration
python examples/advanced/04_ai_integration.py --test
```

## 📊 Performance Optimization

### Parallel Processing

```python
# examples/advanced/parallel_analysis.py
from concurrent.futures import ProcessPoolExecutor
import multiprocessing

def analyze_binary(binary_path):
    """Analyze single binary"""
    analyzer = REVENGAnalyzer(binary_path)
    return analyzer.analyze_binary()

# Process binaries in parallel
binary_files = ["binary1.exe", "binary2.exe", "binary3.exe"]
with ProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
    results = list(executor.map(analyze_binary, binary_files))
```

### Memory Management

```python
# examples/advanced/memory_efficient.py
import gc
from reveng_analyzer import REVENGAnalyzer

def analyze_with_cleanup(binary_path):
    """Analyze with memory cleanup"""
    analyzer = REVENGAnalyzer(binary_path)
    try:
        result = analyzer.analyze_binary()
        return result
    finally:
        # Cleanup
        del analyzer
        gc.collect()
```

## 🔧 Configuration

### Advanced Configuration

```python
# examples/advanced/config.py
ANALYSIS_CONFIG = {
    'timeout': 600,
    'max_functions': 1000,
    'enable_ai': True,
    'ai_provider': 'ollama',
    'ai_model': 'phi',
    'output_format': 'json',
    'verbose': True,
    'debug': False
}

ENHANCED_FEATURES = {
    'corporate_exposure': True,
    'vulnerability_discovery': True,
    'threat_intelligence': True,
    'binary_reconstruction': True,
    'demonstration_generation': True
}

AI_CONFIG = {
    'ollama_host': 'http://localhost:11434',
    'anthropic_api_key': '',
    'openai_api_key': '',
    'timeout': 30
}
```

### Environment Setup

```bash
# Set environment variables
export REVENG_AI_PROVIDER=ollama
export REVENG_AI_MODEL=phi
export REVENG_TIMEOUT=600
export REVENG_VERBOSE=true
```

## 📚 Learning Path

### Step 1: Custom Analyzers
1. Study `01_custom_analyzer.py`
2. Create your own analyzer
3. Test with different binary types

### Step 2: Plugin Development
1. Learn plugin architecture
2. Develop custom plugins
3. Integrate with main system

### Step 3: Batch Processing
1. Understand parallel processing
2. Optimize for performance
3. Handle large datasets

### Step 4: AI Integration
1. Set up AI services
2. Configure AI providers
3. Leverage AI capabilities

### Step 5: Enterprise Features
1. Enable enterprise features
2. Configure security settings
3. Implement audit logging

## 🐛 Troubleshooting

### Common Issues

1. **AI Service Errors**:
   ```bash
   # Check AI service status
   ollama list
   curl http://localhost:11434/api/tags
   ```

2. **Memory Issues**:
   ```bash
   # Monitor memory usage
   python examples/advanced/03_batch_processing.py --memory-limit 4GB
   ```

3. **Performance Issues**:
   ```bash
   # Profile performance
   python examples/advanced/01_custom_analyzer.py --profile
   ```

### Debug Mode

```bash
# Enable debug logging
python examples/advanced/01_custom_analyzer.py --debug

# Verbose output
python examples/advanced/03_batch_processing.py --verbose

# Step-by-step analysis
python examples/advanced/04_ai_integration.py --step-by-step
```

## 📖 Related Documentation

- **[Main Examples README](../README.md)** - All examples overview
- **[Basic Examples](../basic/README.md)** - Basic usage examples
- **[Installation Guide](../../INSTALLATION.md)** - Setup instructions
- **[API Reference](../../API_REFERENCE.md)** - Python API
- **[Architecture](../../ARCHITECTURE.md)** - System design

---

**Advanced Examples** - Master REVENG's powerful features
