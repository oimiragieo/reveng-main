# Advanced Analysis Guide

## Overview

This guide covers advanced analysis techniques using REVENG, including multi-language analysis, automated pipelines, and ML-powered features. It's designed for security researchers, malware analysts, and reverse engineers who need comprehensive binary analysis capabilities.

## Table of Contents

1. [Multi-Language Analysis](#multi-language-analysis)
2. [Automated Analysis Pipelines](#automated-analysis-pipelines)
3. [ML-Powered Analysis](#ml-powered-analysis)
4. [Advanced PE Analysis](#advanced-pe-analysis)
5. [Behavioral Analysis](#behavioral-analysis)
6. [Memory Forensics](#memory-forensics)
7. [Anti-Analysis Bypass](#anti-analysis-bypass)
8. [Custom Analysis Workflows](#custom-analysis-workflows)
9. [Performance Optimization](#performance-optimization)
10. [Troubleshooting](#troubleshooting)

---

## Multi-Language Analysis

### Java Bytecode Analysis

#### CFR Decompilation
```bash
# Analyze Java JAR file
reveng analyze app.jar --language java --decompiler cfr

# Advanced CFR options
reveng analyze app.jar --language java --decompiler cfr \
  --cfr-options "--decodefinally --decodeenumswitch --decodestringswitch"
```

#### Fernflower Decompilation
```bash
# Use Fernflower for better control flow
reveng analyze app.jar --language java --decompiler fernflower

# Fernflower with specific options
reveng analyze app.jar --language java --decompiler fernflower \
  --fernflower-options "--dgs=1 --rsy=1 --lit=1"
```

#### Procyon Decompilation
```bash
# Use Procyon for complex applications
reveng analyze app.jar --language java --decompiler procyon

# Procyon with advanced options
reveng analyze app.jar --language java --decompiler procyon \
  --procyon-options "--package-hierarchy --merge-switch-statements"
```

### .NET Assembly Analysis

#### ILSpy Integration
```bash
# Analyze .NET assembly
reveng analyze app.exe --language dotnet --decompiler ilspy

# ILSpy with specific options
reveng analyze app.exe --language dotnet --decompiler ilspy \
  --ilspy-options "--language C# --output-mode SingleFile"
```

#### DnSpy Integration
```bash
# Use DnSpy for debugging and analysis
reveng analyze app.exe --language dotnet --decompiler dnspy

# DnSpy with debugging enabled
reveng analyze app.exe --language dotnet --decompiler dnspy \
  --dnspy-options "--debug --break-on-entry"
```

#### .NET Framework Detection
```bash
# Detect .NET framework version
reveng analyze app.exe --language dotnet --framework-detect

# Force specific framework version
reveng analyze app.exe --language dotnet --framework 4.8
```

### Python Bytecode Analysis

#### Uncompyle6 Integration
```bash
# Analyze Python bytecode
reveng analyze app.pyc --language python --decompiler uncompyle6

# Uncompyle6 with specific Python version
reveng analyze app.pyc --language python --decompiler uncompyle6 \
  --python-version 3.9
```

#### Decompyle3 Integration
```bash
# Use Decompyle3 for Python 3.7+
reveng analyze app.pyc --language python --decompiler decompyle3

# Decompyle3 with advanced options
reveng analyze app.pyc --language python --decompiler decompyle3 \
  --decompyle3-options "--show-source --show-ast"
```

### Native Binary Analysis

#### Ghidra Integration
```bash
# Analyze native binary with Ghidra
reveng analyze app.exe --language native --decompiler ghidra

# Ghidra with specific architecture
reveng analyze app.exe --language native --decompiler ghidra \
  --architecture x86_64
```

#### IDA Pro Integration
```bash
# Use IDA Pro for advanced analysis
reveng analyze app.exe --language native --decompiler ida

# IDA Pro with specific options
reveng analyze app.exe --language native --decompiler ida \
  --ida-options "--auto-analyze --create-database"
```

---

## Automated Analysis Pipelines

### Pre-built Pipelines

#### Malware Analysis Pipeline
```bash
# Run comprehensive malware analysis
reveng pipeline malware sample.exe --output results/

# Pipeline with specific options
reveng pipeline malware sample.exe \
  --output results/ \
  --include-memory-analysis \
  --include-behavioral-monitoring \
  --threat-intelligence
```

#### .NET Analysis Pipeline
```bash
# Run .NET-specific analysis
reveng pipeline dotnet app.exe --output results/

# .NET pipeline with advanced options
reveng pipeline dotnet app.exe \
  --output results/ \
  --include-resource-extraction \
  --include-api-analysis \
  --include-business-logic
```

#### Quick Triage Pipeline
```bash
# Fast triage analysis
reveng pipeline triage sample.exe --output results/

# Triage with specific focus
reveng pipeline triage sample.exe \
  --output results/ \
  --focus malware \
  --include-threat-intelligence
```

#### Deep Analysis Pipeline
```bash
# Comprehensive deep analysis
reveng pipeline deep sample.exe --output results/

# Deep analysis with all features
reveng pipeline deep sample.exe \
  --output results/ \
  --include-ml-analysis \
  --include-memory-forensics \
  --include-behavioral-monitoring
```

### Custom Pipeline Creation

#### Pipeline Definition
```yaml
# custom-pipeline.yaml
name: custom_malware_analysis
description: Custom malware analysis pipeline
version: 1.0

steps:
  - name: file_analysis
    function: analyze_file
    args:
      binary_path: "{{binary_path}}"
      include_pe_analysis: true
      include_strings: true
      include_imports: true

  - name: pe_resource_extraction
    function: extract_pe_resources
    args:
      binary_path: "{{binary_path}}"
      output_dir: "{{output_dir}}/resources"
    depends_on: ["file_analysis"]

  - name: import_analysis
    function: analyze_imports
    args:
      binary_path: "{{binary_path}}"
      categorize_apis: true
      detect_suspicious: true
    depends_on: ["file_analysis"]

  - name: behavioral_analysis
    function: analyze_behavior
    args:
      binary_path: "{{binary_path}}"
      monitor_file_ops: true
      monitor_registry: true
      monitor_network: true
    depends_on: ["import_analysis"]

  - name: ml_analysis
    function: ml_analyze
    args:
      binary_path: "{{binary_path}}"
      include_reconstruction: true
      include_anomaly_detection: true
      include_threat_intelligence: true
    depends_on: ["behavioral_analysis"]

  - name: generate_report
    function: generate_report
    args:
      output_dir: "{{output_dir}}"
      format: "html"
      include_ml_results: true
    depends_on: ["ml_analysis"]
```

#### Pipeline Execution
```bash
# Run custom pipeline
reveng pipeline custom-pipeline.yaml sample.exe --output results/

# Pipeline with custom variables
reveng pipeline custom-pipeline.yaml sample.exe \
  --output results/ \
  --variables "binary_path=sample.exe,output_dir=results/"
```

---

## ML-Powered Analysis

### Code Reconstruction

#### Basic Reconstruction
```bash
# ML-powered code reconstruction
reveng ml reconstruct sample.exe --output reconstructed/

# Reconstruction with specific model
reveng ml reconstruct sample.exe \
  --model codebert \
  --output reconstructed/ \
  --include-comments
```

#### Advanced Reconstruction
```bash
# Multi-task reconstruction
reveng ml reconstruct sample.exe \
  --tasks decompilation function variable control_flow \
  --model codet5 \
  --output reconstructed/ \
  --include-threat-intelligence
```

### Anomaly Detection

#### Behavioral Anomaly Detection
```bash
# Detect behavioral anomalies
reveng ml anomaly sample.exe --types behavioral

# Multiple anomaly types
reveng ml anomaly sample.exe \
  --types behavioral structural statistical pattern temporal \
  --output results/
```

#### Custom Anomaly Detection
```bash
# Custom anomaly detection with specific features
reveng ml anomaly sample.exe \
  --types behavioral structural \
  --features entropy api_patterns string_analysis \
  --output results/
```

### Threat Intelligence

#### Basic Threat Analysis
```bash
# Generate threat intelligence
reveng ml threat sample.exe --output results/

# Threat analysis with specific model
reveng ml threat sample.exe \
  --model claude \
  --output results/ \
  --include-mitigation
```

#### Advanced Threat Analysis
```bash
# Comprehensive threat analysis
reveng ml threat sample.exe \
  --model gpt \
  --include-categorization \
  --include-confidence-scoring \
  --include-mitigation-recommendations \
  --output results/
```

### ML Model Management

#### Model Status
```bash
# Check ML model status
reveng ml status

# Detailed model information
reveng ml status --verbose
```

#### Model Configuration
```bash
# Configure ML models
reveng ml config --model codebert --enable
reveng ml config --model codet5 --enable
reveng ml config --model gpt --api-key YOUR_API_KEY
```

---

## Advanced PE Analysis

### PE Resource Extraction

#### Icon Extraction
```bash
# Extract all icons from PE file
reveng pe resources sample.exe --extract-icons --output icons/

# Extract specific icon sizes
reveng pe resources sample.exe \
  --extract-icons \
  --icon-sizes 16,32,48,256 \
  --output icons/
```

#### Version Information
```bash
# Extract version information
reveng pe resources sample.exe --extract-version --output version/

# Version information with specific details
reveng pe resources sample.exe \
  --extract-version \
  --include-file-version \
  --include-product-version \
  --include-company-name \
  --output version/
```

#### Manifest Extraction
```bash
# Extract application manifests
reveng pe resources sample.exe --extract-manifests --output manifests/

# Manifest analysis
reveng pe resources sample.exe \
  --extract-manifests \
  --analyze-manifests \
  --output manifests/
```

#### Custom Resources
```bash
# Extract custom resources
reveng pe resources sample.exe --extract-custom --output custom/

# Custom resource analysis
reveng pe resources sample.exe \
  --extract-custom \
  --analyze-custom \
  --output custom/
```

### Import/Export Table Analysis

#### Import Analysis
```bash
# Analyze import table
reveng pe imports sample.exe --output imports/

# Advanced import analysis
reveng pe imports sample.exe \
  --categorize-apis \
  --detect-suspicious \
  --analyze-behavioral-patterns \
  --output imports/
```

#### Export Analysis
```bash
# Analyze export table
reveng pe exports sample.exe --output exports/

# Export analysis with categorization
reveng pe exports sample.exe \
  --categorize-exports \
  --analyze-export-patterns \
  --output exports/
```

#### API Categorization
```bash
# Categorize APIs by functionality
reveng pe imports sample.exe --categorize --output categorized/

# Custom API categorization
reveng pe imports sample.exe \
  --categorize \
  --custom-categories malware_apis.txt \
  --output categorized/
```

### PE Section Analysis

#### Section Information
```bash
# Analyze PE sections
reveng pe sections sample.exe --output sections/

# Section analysis with entropy
reveng pe sections sample.exe \
  --analyze-sections \
  --calculate-entropy \
  --detect-packed-sections \
  --output sections/
```

#### Section Extraction
```bash
# Extract specific sections
reveng pe sections sample.exe --extract-sections .text .data --output extracted/

# Extract all sections
reveng pe sections sample.exe --extract-all-sections --output extracted/
```

---

## Behavioral Analysis

### Process Monitoring

#### Basic Process Monitoring
```bash
# Monitor process behavior
reveng behavioral sample.exe --monitor-process --output behavior/

# Process monitoring with specific events
reveng behavioral sample.exe \
  --monitor-process \
  --events process_creation process_termination \
  --output behavior/
```

#### Advanced Process Monitoring
```bash
# Comprehensive process monitoring
reveng behavioral sample.exe \
  --monitor-process \
  --include-thread-creation \
  --include-memory-allocation \
  --include-api-calls \
  --output behavior/
```

### File System Monitoring

#### File Operations
```bash
# Monitor file operations
reveng behavioral sample.exe --monitor-files --output behavior/

# File monitoring with specific operations
reveng behavioral sample.exe \
  --monitor-files \
  --operations create read write delete \
  --output behavior/
```

#### Registry Monitoring
```bash
# Monitor registry operations
reveng behavioral sample.exe --monitor-registry --output behavior/

# Registry monitoring with specific keys
reveng behavioral sample.exe \
  --monitor-registry \
  --keys "HKEY_LOCAL_MACHINE\\SOFTWARE" \
  --output behavior/
```

### Network Monitoring

#### Network Activity
```bash
# Monitor network activity
reveng behavioral sample.exe --monitor-network --output behavior/

# Network monitoring with specific protocols
reveng behavioral sample.exe \
  --monitor-network \
  --protocols tcp udp http https \
  --output behavior/
```

#### DNS Monitoring
```bash
# Monitor DNS queries
reveng behavioral sample.exe --monitor-dns --output behavior/

# DNS monitoring with filtering
reveng behavioral sample.exe \
  --monitor-dns \
  --filter-suspicious-domains \
  --output behavior/
```

---

## Memory Forensics

### Process Memory Dumping

#### Basic Memory Dumping
```bash
# Dump process memory
reveng memory sample.exe --dump-memory --output memory/

# Memory dumping with specific regions
reveng memory sample.exe \
  --dump-memory \
  --regions heap stack code \
  --output memory/
```

#### Advanced Memory Dumping
```bash
# Comprehensive memory dumping
reveng memory sample.exe \
  --dump-memory \
  --include-all-regions \
  --include-memory-maps \
  --output memory/
```

### Memory Analysis

#### String Extraction
```bash
# Extract strings from memory
reveng memory sample.exe --extract-strings --output strings/

# String extraction with filtering
reveng memory sample.exe \
  --extract-strings \
  --filter-strings \
  --min-length 4 \
  --output strings/
```

#### Heap Analysis
```bash
# Analyze heap memory
reveng memory sample.exe --analyze-heap --output heap/

# Heap analysis with specific features
reveng memory sample.exe \
  --analyze-heap \
  --include-allocations \
  --include-freed-blocks \
  --output heap/
```

#### Credential Harvesting
```bash
# Harvest credentials from memory
reveng memory sample.exe --harvest-credentials --output credentials/

# Credential harvesting with specific types
reveng memory sample.exe \
  --harvest-credentials \
  --types passwords tokens keys \
  --output credentials/
```

---

## Anti-Analysis Bypass

### Packing Detection

#### Basic Packing Detection
```bash
# Detect packed binaries
reveng analyze sample.exe --detect-packing

# Packing detection with specific tools
reveng analyze sample.exe \
  --detect-packing \
  --tools detect-it-easy exeinfo-pe \
  --output packing/
```

#### Advanced Packing Detection
```bash
# Comprehensive packing detection
reveng analyze sample.exe \
  --detect-packing \
  --include-entropy-analysis \
  --include-section-analysis \
  --include-import-analysis \
  --output packing/
```

### Unpacking

#### Automatic Unpacking
```bash
# Attempt automatic unpacking
reveng analyze sample.exe --unpack --output unpacked/

# Unpacking with specific tools
reveng analyze sample.exe \
  --unpack \
  --tools scylla x64dbg \
  --output unpacked/
```

#### Manual Unpacking
```bash
# Manual unpacking with debugging
reveng analyze sample.exe \
  --unpack \
  --method manual \
  --debugger x64dbg \
  --output unpacked/
```

### Anti-Debugging Bypass

#### Anti-Debugging Detection
```bash
# Detect anti-debugging techniques
reveng analyze sample.exe --detect-anti-debugging

# Anti-debugging detection with specific techniques
reveng analyze sample.exe \
  --detect-anti-debugging \
  --techniques isdebuggerpresent checkremotedebuggerpresent \
  --output anti-debug/
```

#### Anti-Debugging Bypass
```bash
# Bypass anti-debugging techniques
reveng analyze sample.exe \
  --bypass-anti-debugging \
  --techniques patch-apis hook-apis \
  --output bypassed/
```

---

## Custom Analysis Workflows

### Workflow Definition

#### Basic Workflow
```yaml
# custom-workflow.yaml
name: custom_analysis_workflow
description: Custom analysis workflow
version: 1.0

steps:
  - name: initial_analysis
    function: analyze_file
    args:
      binary_path: "{{binary_path}}"
      include_basic_analysis: true

  - name: pe_analysis
    function: analyze_pe
    args:
      binary_path: "{{binary_path}}"
      include_resources: true
      include_imports: true
    depends_on: ["initial_analysis"]

  - name: behavioral_analysis
    function: analyze_behavior
    args:
      binary_path: "{{binary_path}}"
      monitor_all: true
    depends_on: ["pe_analysis"]

  - name: ml_analysis
    function: ml_analyze
    args:
      binary_path: "{{binary_path}}"
      include_all_features: true
    depends_on: ["behavioral_analysis"]

  - name: generate_report
    function: generate_report
    args:
      output_dir: "{{output_dir}}"
      format: "html"
    depends_on: ["ml_analysis"]
```

#### Advanced Workflow
```yaml
# advanced-workflow.yaml
name: advanced_analysis_workflow
description: Advanced analysis workflow
version: 1.0

steps:
  - name: file_analysis
    function: analyze_file
    args:
      binary_path: "{{binary_path}}"
      include_pe_analysis: true
      include_strings: true
      include_imports: true

  - name: pe_resource_extraction
    function: extract_pe_resources
    args:
      binary_path: "{{binary_path}}"
      output_dir: "{{output_dir}}/resources"
    depends_on: ["file_analysis"]

  - name: import_analysis
    function: analyze_imports
    args:
      binary_path: "{{binary_path}}"
      categorize_apis: true
      detect_suspicious: true
    depends_on: ["file_analysis"]

  - name: behavioral_analysis
    function: analyze_behavior
    args:
      binary_path: "{{binary_path}}"
      monitor_file_ops: true
      monitor_registry: true
      monitor_network: true
    depends_on: ["import_analysis"]

  - name: memory_analysis
    function: analyze_memory
    args:
      binary_path: "{{binary_path}}"
      dump_memory: true
      extract_strings: true
      analyze_heap: true
    depends_on: ["behavioral_analysis"]

  - name: ml_analysis
    function: ml_analyze
    args:
      binary_path: "{{binary_path}}"
      include_reconstruction: true
      include_anomaly_detection: true
      include_threat_intelligence: true
    depends_on: ["memory_analysis"]

  - name: generate_report
    function: generate_report
    args:
      output_dir: "{{output_dir}}"
      format: "html"
      include_ml_results: true
      include_memory_results: true
    depends_on: ["ml_analysis"]
```

### Workflow Execution

#### Basic Execution
```bash
# Run custom workflow
reveng workflow custom-workflow.yaml sample.exe --output results/

# Workflow with custom variables
reveng workflow custom-workflow.yaml sample.exe \
  --output results/ \
  --variables "binary_path=sample.exe,output_dir=results/"
```

#### Advanced Execution
```bash
# Run advanced workflow
reveng workflow advanced-workflow.yaml sample.exe \
  --output results/ \
  --parallel \
  --timeout 3600 \
  --retry-failed-steps
```

---

## Performance Optimization

### Parallel Processing

#### Basic Parallel Processing
```bash
# Enable parallel processing
reveng analyze sample.exe --parallel --output results/

# Parallel processing with specific options
reveng analyze sample.exe \
  --parallel \
  --max-workers 4 \
  --output results/
```

#### Advanced Parallel Processing
```bash
# Advanced parallel processing
reveng analyze sample.exe \
  --parallel \
  --max-workers 8 \
  --chunk-size 1024 \
  --output results/
```

### Caching

#### Basic Caching
```bash
# Enable caching
reveng analyze sample.exe --cache --output results/

# Caching with specific options
reveng analyze sample.exe \
  --cache \
  --cache-dir ~/.reveng/cache \
  --output results/
```

#### Advanced Caching
```bash
# Advanced caching
reveng analyze sample.exe \
  --cache \
  --cache-dir ~/.reveng/cache \
  --cache-size 1GB \
  --cache-ttl 3600 \
  --output results/
```

### Memory Management

#### Basic Memory Management
```bash
# Enable memory management
reveng analyze sample.exe --memory-management --output results/

# Memory management with specific options
reveng analyze sample.exe \
  --memory-management \
  --max-memory 2GB \
  --output results/
```

#### Advanced Memory Management
```bash
# Advanced memory management
reveng analyze sample.exe \
  --memory-management \
  --max-memory 4GB \
  --memory-cleanup \
  --output results/
```

---

## Troubleshooting

### Common Issues

#### Dependency Issues
```bash
# Check dependencies
reveng setup --check-dependencies

# Install missing dependencies
reveng setup --install-dependencies

# Update dependencies
reveng setup --update-dependencies
```

#### Analysis Failures
```bash
# Debug analysis failures
reveng analyze sample.exe --debug --output results/

# Verbose output
reveng analyze sample.exe --verbose --output results/

# Log analysis
reveng analyze sample.exe --log-level debug --output results/
```

#### Performance Issues
```bash
# Profile analysis
reveng analyze sample.exe --profile --output results/

# Performance analysis
reveng analyze sample.exe --performance --output results/

# Memory usage analysis
reveng analyze sample.exe --memory-usage --output results/
```

### Error Handling

#### Common Errors
- **Missing Dependencies**: Install required tools
- **Analysis Failures**: Check binary format and permissions
- **Memory Issues**: Increase memory limits or use streaming
- **Timeout Issues**: Increase timeout or use parallel processing

#### Debugging
```bash
# Enable debug mode
reveng analyze sample.exe --debug --output results/

# Verbose logging
reveng analyze sample.exe --log-level debug --output results/

# Error reporting
reveng analyze sample.exe --error-reporting --output results/
```

---

## Best Practices

### Analysis Workflow

1. **Start with Basic Analysis**: Always begin with basic file analysis
2. **Use Appropriate Tools**: Select tools based on binary type and analysis goals
3. **Combine Multiple Approaches**: Use static, dynamic, and ML analysis together
4. **Document Results**: Keep detailed records of analysis results
5. **Validate Findings**: Cross-reference findings with multiple tools

### Performance Optimization

1. **Use Parallel Processing**: Enable parallel processing for large files
2. **Implement Caching**: Use caching for repeated analysis operations
3. **Memory Management**: Monitor and manage memory usage
4. **Resource Cleanup**: Ensure proper cleanup of temporary files

### Security Considerations

1. **Sandboxing**: Use sandboxed environments for malware analysis
2. **Network Isolation**: Isolate network access during analysis
3. **Data Protection**: Protect sensitive analysis data
4. **Access Control**: Implement proper access controls

---

*This guide provides comprehensive coverage of advanced analysis techniques using REVENG. For more specific information, refer to the individual tool documentation and case studies.*
