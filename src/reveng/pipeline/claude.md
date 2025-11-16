# Directory: src/reveng/pipeline

## Overview
This directory contains the automated analysis pipeline engine that orchestrates complex multi-stage binary analysis workflows. The pipeline engine supports tool chaining, error handling, retry logic, result aggregation, and prebuilt analysis workflows for common use cases.

## Files in This Directory

### __init__.py
- **Purpose**: Package initialization, exports pipeline steps module
- **Key Classes**: None
- **Key Functions**: None
- **Dependencies**: `.steps`
- **Used By**: Analyzer, API, CLI

### pipeline_engine.py
- **Purpose**: Core automated analysis pipeline with tool chaining and workflow orchestration
- **Key Classes**:
  - `AnalysisPipeline`: Main pipeline orchestrator
  - `Pipeline`: Pipeline definition dataclass
  - `PipelineStage`: Stage definition dataclass
  - `StageResult`: Stage execution result dataclass
  - `PipelineResult`: Complete pipeline execution result
  - `PipelineStatus`: Enum for pipeline status (PENDING, RUNNING, COMPLETED, FAILED, CANCELLED)
  - `StageStatus`: Enum for stage status (PENDING, RUNNING, COMPLETED, FAILED, SKIPPED)
  - `StageType`: Enum for stage types (STATIC_ANALYSIS, DYNAMIC_ANALYSIS, PE_ANALYSIS, etc.)
- **Key Functions**:
  - `create_pipeline()`: Create new analysis pipeline
  - `add_stage()`: Add analysis stage to pipeline
  - `execute_pipeline()`: Execute complete pipeline with retry logic
  - `save_pipeline()`: Save pipeline definition to YAML
  - `load_pipeline()`: Load saved pipeline from YAML
  - `get_prebuilt_pipeline()`: Get prebuilt pipeline by name
  - `list_pipelines()`: List available pipelines
  - `_execute_stage()`: Execute single pipeline stage with retries
  - `_execute_static_analysis()`: Static analysis stage execution
  - `_execute_pe_analysis()`: PE analysis stage execution
  - `_execute_ghidra_analysis()`: Ghidra analysis stage execution
  - `_execute_hex_analysis()`: Hex analysis stage execution
  - `_execute_malware_analysis()`: Malware analysis stage execution
  - `_execute_ml_analysis()`: ML analysis stage execution
  - `_execute_report_generation()`: Report generation stage execution
  - `_aggregate_stage_outputs()`: Aggregate outputs from all stages
  - `_load_prebuilt_pipelines()`: Load prebuilt pipeline templates
- **Dependencies**:
  - `..core.errors` (PipelineExecutionError, create_error_context)
  - `..core.logger`
  - `..analyzers.*` (Business logic, .NET analyzers)
  - `..pe.*` (PE resource extraction, import analysis)
  - `..ghidra.scripting_engine`
  - `..tools.hex_editor`
- **Used By**: CLI, API, automated workflows
- **Prebuilt Pipelines**:
  - `malware_analysis`: Complete malware analysis workflow (6 stages)
  - `dotnet_analysis`: .NET application analysis workflow (4 stages)
  - `quick_triage`: Quick binary triage (3 stages)
  - `deep_analysis`: Comprehensive deep-dive analysis (6 stages)

## Architecture

### Pipeline Execution Flow
```
┌─────────────────────────────────────┐
│     Pipeline Definition             │
├─────────────────────────────────────┤
│ - Name                              │
│ - Description                       │
│ - Stages (ordered list)             │
│ - Version                           │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┐
       │  Pipeline       │
       │  Orchestrator   │
       └───────┬─────────┘
               │
       ┌───────┴────────────────┐
       │  Stage Execution Loop  │
       ├────────────────────────┤
       │ For each stage:        │
       │ 1. Check dependencies  │
       │ 2. Execute stage       │
       │ 3. Retry on failure    │
       │ 4. Aggregate results   │
       └────────┬───────────────┘
                │
        ┌───────┴───────────┐
        │  Stage Executors  │
        ├───────────────────┤
        │ - Static Analysis │
        │ - PE Analysis     │
        │ - Ghidra Analysis │
        │ - Hex Analysis    │
        │ - Malware Analysis│
        │ - ML Analysis     │
        │ - Report Gen      │
        └───────┬───────────┘
                │
        ┌───────┴─────────┐
        │  Result         │
        │  Aggregation    │
        └─────────────────┘
```

### Stage Dependencies
Stages can declare dependencies on other stages. The pipeline engine ensures stages execute in correct order and skips dependent stages if required stages fail.

Example dependency chain:
```
static_analysis (no deps)
    └─> pe_analysis (depends on static_analysis)
        └─> hex_analysis (depends on pe_analysis)
            └─> ghidra_analysis (depends on hex_analysis)
                └─> malware_analysis (depends on ghidra_analysis)
                    └─> report_generation (depends on malware_analysis)
```

### Error Handling and Retries
- Each stage has configurable retry count and timeout
- Failed stages can be retried automatically
- If required stage fails, dependent stages are skipped
- Non-required stages can fail without stopping pipeline
- All errors are logged and included in final report

## Key Concepts

### Pipeline Composition
Pipelines are composed of ordered stages. Each stage:
- Has a unique name
- Specifies a stage type (static, dynamic, PE, Ghidra, etc.)
- Declares dependencies on other stages
- Has timeout and retry configuration
- Can be marked as required or optional

### Stage Types
The pipeline supports these stage types:
- **STATIC_ANALYSIS**: .NET analysis, business logic extraction
- **DYNAMIC_ANALYSIS**: Runtime behavior analysis (placeholder)
- **PE_ANALYSIS**: PE resource extraction, import/export analysis
- **GHIDRA_ANALYSIS**: Ghidra-based disassembly and decompilation
- **HEX_ANALYSIS**: Hex-level analysis, entropy, pattern matching
- **MALWARE_ANALYSIS**: Malware-specific analysis (placeholder)
- **ML_ANALYSIS**: Machine learning analysis (placeholder)
- **REPORT_GENERATION**: HTML/Markdown report generation

### Prebuilt Workflows
Four prebuilt pipelines are available:

1. **Malware Analysis** (6 stages, ~35 min):
   - Static analysis (5 min)
   - PE analysis (5 min)
   - Hex analysis (5 min)
   - Ghidra analysis (10 min)
   - Malware analysis (5 min)
   - Report generation (1 min)

2. **.NET Analysis** (4 stages, ~11 min):
   - .NET analysis (5 min)
   - PE resources (5 min)
   - Business logic (5 min)
   - Report generation (1 min)

3. **Quick Triage** (3 stages, ~6 min):
   - Static analysis (2 min)
   - PE analysis (2 min)
   - Hex analysis (2 min)

4. **Deep Analysis** (6 stages, ~52 min):
   - Static analysis (10 min)
   - PE analysis (10 min)
   - Hex analysis (10 min)
   - Ghidra analysis (20 min)
   - ML analysis (10 min)
   - Report generation (2 min)

### Pipeline Persistence
Pipelines can be saved to and loaded from YAML files for reuse:

```yaml
name: custom_analysis
description: My custom analysis workflow
version: 1.0
created: 2025-01-15 12:00:00
stages:
  - name: static_analysis
    stage_type: STATIC_ANALYSIS
    tool: reveng
    config:
      dotnet_analysis: true
    dependencies: []
    timeout: 300
    retry_count: 3
    required: true
```

## Usage Examples

### Using Prebuilt Pipelines
```python
from reveng.pipeline.pipeline_engine import AnalysisPipeline

# Create pipeline engine
engine = AnalysisPipeline()

# List available pipelines
pipelines = engine.list_pipelines()
print(f"Available: {pipelines}")
# Output: ['malware_analysis', 'dotnet_analysis', 'quick_triage', 'deep_analysis']

# Get prebuilt pipeline
malware_pipeline = engine.get_prebuilt_pipeline("malware_analysis")

# Execute pipeline
result = engine.execute_pipeline(malware_pipeline, "suspicious.exe")

# Check results
print(f"Pipeline: {result.pipeline_name}")
print(f"Status: {result.status}")
print(f"Success: {result.success_count}/{result.success_count + result.failure_count}")
print(f"Time: {result.total_execution_time:.2f} seconds")

# Access stage results
for stage in result.stage_results:
    print(f"Stage {stage.stage_name}: {stage.status.value}")
    if stage.error:
        print(f"  Error: {stage.error}")
```

### Creating Custom Pipelines
```python
from reveng.pipeline.pipeline_engine import (
    AnalysisPipeline,
    PipelineStage,
    StageType
)

# Create pipeline engine
engine = AnalysisPipeline()

# Create new pipeline
pipeline = engine.create_pipeline(
    name="my_analysis",
    description="Custom analysis workflow"
)

# Add stages
engine.add_stage(pipeline, PipelineStage(
    name="static",
    stage_type=StageType.STATIC_ANALYSIS,
    tool="reveng",
    config={"dotnet_analysis": True},
    dependencies=[],
    timeout=300,
    retry_count=3,
    required=True
))

engine.add_stage(pipeline, PipelineStage(
    name="pe",
    stage_type=StageType.PE_ANALYSIS,
    tool="reveng",
    config={"resource_extraction": True},
    dependencies=["static"],
    timeout=300,
    retry_count=2,
    required=False  # Optional stage
))

# Execute
result = engine.execute_pipeline(pipeline, "app.exe")

# Save for reuse
engine.save_pipeline(pipeline, "my_analysis.yaml")
```

### Loading and Using Saved Pipelines
```python
from reveng.pipeline.pipeline_engine import AnalysisPipeline

engine = AnalysisPipeline()

# Load saved pipeline
pipeline = engine.load_pipeline("my_analysis.yaml")

# Execute on multiple binaries
for binary in ["app1.exe", "app2.exe", "app3.exe"]:
    result = engine.execute_pipeline(pipeline, binary)
    print(f"{binary}: {result.status.value}")
```

### Accessing Stage Results
```python
result = engine.execute_pipeline(pipeline, "malware.exe")

# Get specific stage output
for stage in result.stage_results:
    if stage.stage_name == "pe_analysis":
        imports = stage.output.get("imports", {})
        resources = stage.output.get("resources", {})
        print(f"Imports: {imports}")
        print(f"Resources: {resources}")

# Get aggregated output
aggregated = result.output
print(f"All stage outputs: {aggregated}")
```

## Configuration

### Stage Configuration
Each stage can have custom configuration:

```python
PipelineStage(
    name="ghidra_deep",
    stage_type=StageType.GHIDRA_ANALYSIS,
    tool="ghidra",
    config={
        "auto_analyze": True,
        "decompile": True,
        "call_graph": True,
        "data_flow": True,
        "max_functions": 1000
    },
    dependencies=["hex_analysis"],
    timeout=1200,  # 20 minutes
    retry_count=3,
    required=True
)
```

### Timeout and Retry Settings
- `timeout`: Maximum execution time in seconds
- `retry_count`: Number of retries on failure
- `required`: If True, pipeline stops on failure

### Tool Selection
The `tool` field specifies which tool to use:
- `"reveng"`: REVENG internal analyzers
- `"ghidra"`: Ghidra Analysis Server
- Custom tools can be added

## Testing

### Unit Tests
```bash
# Test pipeline creation
pytest tests/pipeline/test_pipeline_engine.py::test_create_pipeline

# Test stage execution
pytest tests/pipeline/test_pipeline_engine.py::test_execute_stage

# Test error handling
pytest tests/pipeline/test_pipeline_engine.py::test_error_handling
```

### Integration Tests
```bash
# Test full pipeline execution
pytest tests/pipeline/test_integration.py::test_full_pipeline

# Test prebuilt pipelines
pytest tests/pipeline/test_integration.py::test_prebuilt_pipelines
```

## Related Modules

### Dependencies
- `src/reveng/core/errors`: Error handling framework
- `src/reveng/core/logger`: Logging utilities
- `src/reveng/analyzers/`: Static analyzers (business logic, .NET)
- `src/reveng/pe/`: PE analysis tools
- `src/reveng/ghidra/`: Ghidra integration
- `src/reveng/tools/`: Various analysis tools
- `src/reveng/pipeline/steps/`: Step implementations

### Used By
- `src/reveng/analyzer.py`: Main analyzer uses pipeline for step orchestration
- `src/reveng/api.py`: API exposes pipeline execution
- `src/reveng/cli.py`: CLI allows pipeline execution

## Notes

### Performance Considerations
- Pipelines execute stages sequentially (no parallelization yet)
- Stage timeouts prevent hanging on large binaries
- Retry logic can significantly increase execution time
- Quick triage pipeline is optimized for speed (<6 min)
- Deep analysis pipeline is optimized for thoroughness (~52 min)

### Error Recovery
- Automatic retry on transient failures
- Graceful degradation when optional stages fail
- Detailed error messages in results
- Pipeline continues after non-required stage failures

### Extensibility
To add new stage types:
1. Add new `StageType` enum value
2. Implement `_execute_<type>()` method
3. Update `_execute_stage()` dispatcher
4. Add to prebuilt pipelines if needed

### Best Practices
1. Mark critical stages as `required=True`
2. Set appropriate timeouts based on binary size
3. Use dependencies to enforce execution order
4. Save custom pipelines for reuse
5. Monitor stage execution times to optimize
6. Use quick triage for rapid initial assessment
7. Use deep analysis for comprehensive research

### Future Enhancements
- Parallel stage execution (for independent stages)
- Conditional stage execution (based on previous results)
- Dynamic timeout adjustment (based on binary size)
- Pipeline scheduling and queuing
- Distributed pipeline execution
- Real-time progress reporting
- Pipeline visualization (DAG view)
- Stage result caching
