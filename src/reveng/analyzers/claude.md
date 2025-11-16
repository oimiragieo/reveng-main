# Directory: src/reveng/analyzers

## Overview
This directory contains specialized analyzers for extracting business logic, analyzing .NET assemblies, and understanding application domain knowledge. These analyzers help reverse engineers understand the high-level purpose and functionality of applications.

## Files in This Directory

### business_logic_analyzer.py
- **Purpose**: Analyze business logic and application workflows
- **Key Classes**: `BusinessLogicAnalyzer`
- **Key Functions**:
  - `analyze()`: Comprehensive business logic analysis
  - `extract_workflows()`: Extract business workflows
  - `identify_patterns()`: Identify common business patterns
  - `map_data_flow()`: Map data flow through application

### business_logic_extractor.py
- **Purpose**: Extract business logic from binaries
- **Key Classes**: `BusinessLogicExtractor`
- **Key Functions**:
  - `analyze_application_domain()`: Understand application domain
  - `extract_entities()`: Extract business entities
  - `extract_rules()`: Extract business rules
  - `extract_processes()`: Extract business processes

### dotnet_analyzer.py
- **Purpose**: Analyze .NET assemblies
- **Key Classes**: `DotNetAnalyzer`
- **Key Functions**:
  - `analyze_assembly()`: Analyze .NET assembly
  - `extract_metadata()`: Extract assembly metadata
  - `analyze_types()`: Analyze types and classes
  - `analyze_dependencies()`: Analyze assembly dependencies
  - `detect_obfuscation()`: Detect .NET obfuscation

## Architecture

```
┌─────────────────────────────────────┐
│   High-Level Analyzers              │
├─────────────────────────────────────┤
│ • Business Logic Analysis           │
│ • Domain Knowledge Extraction       │
│ • .NET Assembly Analysis            │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────────────┐
       │   Analysis Results     │
       ├────────────────────────┤
       │ • Entities             │
       │ • Workflows            │
       │ • Business Rules       │
       │ • Data Flow            │
       └────────────────────────┘
```

## Key Concepts

### Business Logic Analysis
Extracts high-level understanding:
- **Business Entities**: Customer, Order, Product, etc.
- **Business Rules**: Validation logic, constraints
- **Workflows**: Multi-step processes
- **Data Flow**: How data moves through application

### Application Domains
Common domains detected:
- E-commerce (shopping carts, payments)
- Banking (transactions, accounts)
- Healthcare (patients, appointments)
- CRM (contacts, leads, sales)
- ERP (inventory, manufacturing)

### .NET Analysis
.NET-specific capabilities:
- Metadata extraction
- Type hierarchy analysis
- Dependency mapping
- Obfuscation detection
- Resource extraction

## Usage Examples

### Business Logic Analysis
```python
from reveng.analyzers.business_logic_analyzer import BusinessLogicAnalyzer

analyzer = BusinessLogicAnalyzer()

# Analyze business logic
result = analyzer.analyze("ecommerce_app.exe")

print(f"Application domain: {result.domain}")
print(f"Business entities: {result.entities}")
print(f"Workflows found: {len(result.workflows)}")

for workflow in result.workflows:
    print(f"\nWorkflow: {workflow.name}")
    print(f"Steps: {workflow.steps}")
```

### Business Logic Extraction
```python
from reveng.analyzers.business_logic_extractor import BusinessLogicExtractor

extractor = BusinessLogicExtractor()

# Extract application domain knowledge
result = extractor.analyze_application_domain("crm_app.exe")

print(f"Domain: {result.domain_name}")
print(f"Confidence: {result.confidence}")

# Extract entities
entities = extractor.extract_entities(result)
for entity in entities:
    print(f"Entity: {entity.name}")
    print(f"  Properties: {entity.properties}")
    print(f"  Relationships: {entity.relationships}")

# Extract business rules
rules = extractor.extract_rules(result)
for rule in rules:
    print(f"Rule: {rule.name}")
    print(f"  Condition: {rule.condition}")
    print(f"  Action: {rule.action}")
```

### .NET Assembly Analysis
```python
from reveng.analyzers.dotnet_analyzer import DotNetAnalyzer

analyzer = DotNetAnalyzer()

# Analyze .NET assembly
result = analyzer.analyze_assembly("MyApp.dll")

print(f"Assembly: {result.name}")
print(f"Version: {result.version}")
print(f"Runtime: {result.target_framework}")
print(f"Types: {result.types_count}")
print(f"Obfuscated: {result.is_obfuscated}")

# Analyze types
types = analyzer.analyze_types(result)
for type_info in types[:10]:
    print(f"\nType: {type_info.name}")
    print(f"  Namespace: {type_info.namespace}")
    print(f"  Methods: {len(type_info.methods)}")
    print(f"  Properties: {len(type_info.properties)}")

# Analyze dependencies
deps = analyzer.analyze_dependencies(result)
print(f"\nDependencies:")
for dep in deps:
    print(f"  - {dep.name} ({dep.version})")
```

## Configuration

### Business Logic Configuration
```python
config = {
    "domain_detection": True,
    "entity_extraction": True,
    "workflow_analysis": True,
    "confidence_threshold": 0.7
}

analyzer = BusinessLogicAnalyzer(config=config)
```

### .NET Analysis Configuration
```python
config = {
    "extract_metadata": True,
    "analyze_il": True,
    "detect_obfuscation": True,
    "extract_resources": True
}

analyzer = DotNetAnalyzer(config=config)
```

## Testing

### Unit Tests
```bash
pytest tests/analyzers/test_business_logic.py
pytest tests/analyzers/test_dotnet_analyzer.py
```

### Integration Tests
```bash
pytest tests/analyzers/test_integration.py
```

## Related Modules

### Dependencies
- `src/reveng/tools/languages/`: Language-specific tools
- Pattern matching engines
- NLP libraries (for business logic)

### Used By
- `src/reveng/pipeline/pipeline_engine.py`: Uses in static analysis stage
- Application reconstruction workflows

## Notes

### Business Logic Detection
Uses multiple techniques:
- String analysis (entity names, field names)
- Code patterns (CRUD operations, validation)
- Database schema inference
- API endpoint analysis
- Configuration file parsing

### Domain Detection Accuracy
- E-commerce: 85-90% accuracy
- Banking: 80-85% accuracy
- Healthcare: 75-80% accuracy
- CRM: 80-85% accuracy
- Generic: 70-75% accuracy

### .NET Support
- Framework: .NET Framework 2.0-4.8
- Core: .NET Core 1.0-3.1
- Modern: .NET 5.0+
- Languages: C#, VB.NET, F#
- Obfuscators: ConfuserEx, .NET Reactor, etc.

### Best Practices
1. Combine with static and dynamic analysis
2. Use domain knowledge to improve accuracy
3. Manually review extracted entities
4. Cross-reference with documentation
5. Validate business rules through testing

### Limitations
- May miss domain-specific logic
- Obfuscation reduces accuracy
- Generic applications harder to classify
- Requires sufficient code coverage

### Performance
- Business logic analysis: 2-5 minutes
- .NET assembly analysis: 1-3 minutes
- Depends on application size and complexity
