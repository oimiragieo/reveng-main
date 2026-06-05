# `claude.md` — `tools/translation`

**Repository path:** `src/reveng/tools/translation/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Code Translation Tools

### `api_mappings.py`
- **Summary:** Windows API to Python mappings database.
- **Classes:**
  - `APIMapping` — Represents a Windows API to Python translation mapping.
- **Functions / coroutines:**
  - `def get_api_mapping()` — Get the Python mapping for a Windows API.
  - `def get_mappings_by_category()` — Get all API mappings in a specific category.
  - `def get_all_categories()` — Get list of all API categories.

### `hint_generator.py`
- **Summary:** Translation hint generator for AI-assisted C-to-Python conversion.
- **Classes:**
  - `TranslationHint` — Represents a translation hint for converting C code to Python.
- **Functions / coroutines:**
  - `def generate_translation_hints()` — Generate comprehensive translation hints for C code.
  - `def generate_summary()` — Generate high-level summary of translation task.
  - `def calculate_coverage()` — Calculate what percentage of detected APIs have known mappings.
  - `def estimate_effort()` — Estimate translation effort based on complexity and hints.
  - `def generate_inline_hints()` — Generate C code with inline translation hints as comments.
  - `def generate_translation_guide()` — Generate a comprehensive translation guide document.

### `pattern_matcher.py`
- **Summary:** Pattern matcher for detecting Windows API calls in C code.
- **Classes:**
  - `APICallMatch` — Represents a detected Windows API call in C code.
- **Functions / coroutines:**
  - `def detect_api_calls()` — Detect Windows API calls in C code.
  - `def extract_variables_from_call()` — Extract variable names used in an API call.
  - `def extract_primary_variable()` — Extract the primary variable name from an argument expression.
  - `def detect_api_patterns()` — Detect common Windows API usage patterns.
  - `def get_translation_complexity()` — Estimate translation complexity based on API calls detected.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
