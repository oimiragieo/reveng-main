# NATIVE RECOMPILATION HARDENING: NEXT 3 PRIORITY FIXES

## FRONT EDGE ANALYSIS

**Current Status**: Hexyl binary reconstruction failing. Recent fixes applied:
- ghidra_vec128/vec64 normalization (lines 973-1051)
- Helper preludes and CONCAT macros (lines 831-860)
- Pointer/integer assignment rewrites (lines 1135-1197)
- Scope-aware pointer prototype relaxation (lines 1219-1266)

**Key Artifact Sources**:
- Latest reconstructed.c: 4.2MB with 2647 functions
- Calls to FUN_14007c630/FUN_14007b260 carrying &local_228 to undefined8* params
- Undeclared _local_228 assignments mixed with declared local_228
- Multiple undefined8-vs-pointer temporaries (uStack_88, local_468, local_460)

---

## PRIORITY #1: UNDECLARED SPLIT-LOCAL NORMALIZATION
**Patterns Found**: _local_228, _local_9c (lines 9912, 11634, 68836)

### The Bug
Ghidra generates separate declarations for overlapping stack temporaries:
- Declared: `ulonglong ***********local_228;` (line 5375)
- Undeclared: `_local_228 = GHIDRA_U128(0x0);` (line 9912)

This occurs when a variable is split across multiple assignments where Ghidra loses type context.

### Why This is Engine Bug
1. **Consistency**: local_228 declared as 11-pointer int (ulonglong*...), but _local_228 used as ghidra_uint128
2. **Cross-context**: Both used in same scope without explicit union/overlay declaration
3. **Scope violation**: _local_228 never declared in function signature, only materialized in assignment
4. **Semantic mismatch**: Compiler cannot correlate them as same variable or separate

### Pattern & Fix

Pattern: `^\s+_([a-z_][a-z0-9_]*)\s*=\s*(GHIDRA_U128|GHIDRA_U64|auVar|uVar|lVar)\s*;`

Normalization:
1. Check if declared version exists: replace `_varname` with `varname`
2. If no declaration found, insert: `uint64_t varname;`
3. Rewrite assignment: `_varname = X` becomes `varname = X`
4. Track in variable_types cache to downstream pointer checks

**Code location**: Add after _extract_declared_variable_types (line 1091)

### Reusability
- Applies to ALL split-local patterns: _local_*, _uStack_*, _puStack_*
- No sample-specific hardcoding needed
- Covers pattern class across all binary sizes
- Safe because it resolves scope errors, doesn't change semantics

### Complexity: LOW | Confidence: VERY HIGH | Impact: MEDIUM

---

## PRIORITY #2: UNDEFINED8* PARAMETER PROTOTYPE WIDENING (CONTEXT-AWARE)
**Patterns Found**: FUN_14007c630, FUN_14007b260, FUN_140050640 (lines 2596, 2682, etc.)

### The Bug
Function declarations expect undefined8 *param_2 but are called with:

```c
// Declaration (line 2682):
void * __fastcall FUN_14007c630(longlong param_1, undefined8 *param_2, ...)

// But param_2 is passed as:
FUN_14007c630(..., &local_228, ...)  // local_228 is ulonglong***********
FUN_14007c630(..., &local_358, ...)  // local_358 is pointer type
FUN_14007c630(..., &local_1f8, ...)  // local_1f8 is pointer type
```

### Why This is Engine Bug (not sample-specific)
1. **Type conflict**: undefined8* expects opaque byte buffer; receives pointer-to-pointer locals
2. **Ghidra dataflow break**: Ghidra can't prove undefined8 param matches pointer argument
3. **Universal pattern**: undefined8* params almost always receive address-of locals in reconstructed code
4. **Compilation fails**: C type mismatch prevents compilation, even though binary intent is clear

### Pattern & Fix

Current code (lines 1250-1256): Only checks first param_0
Problem: param_2, param_3, param_4 also mismatch

Pattern: `undefined8 \*param_([1-9])\b`

Evidence for param at index:
1. Find all calls to function: `FUN_NAME(..., &VAR, ...)`
2. Extract argument at position N
3. Look up declared type of VAR via _find_nearest_declared_variable_type
4. If it contains '*', arg is pointer

**Fix**: Extend _relax_mismatched_pointer_prototypes (line 1219) to handle param_1..param_9:

```python
for index in range(0, len(params_list)):  # NOT just index==0
    param = params_list[index]
    if re.search(r"undefined8\s*\*\s+param_(\d+)", param):
        # Get all calls to this function
        calls = re.finditer(rf"{func_name}\s*\(", source)
        for call in calls:
            # Extract arg at position index
            # Check if it's address-of or pointer type
            # If yes: replace "undefined8 *" with "void *"
```

### Reusability
- Applies to any function with mismatched undefined8* params
- Pattern: undefined8 * param_N where N > 0 and calls pass pointers
- No binary-specific logic
- Handles FUN_14007c630, FUN_14007b260, FUN_140050640, etc. uniformly

### Complexity: MEDIUM | Confidence: HIGH | Impact: MEDIUM-HIGH

---

## PRIORITY #3: TEMPORARY UNDEFINED8-VS-POINTER SPLIT LOCALS
**Patterns Found**: uStack_88, local_468, local_460 (lines 2227-2232, etc.)

### The Bug
Same-name variables have conflicting type uses:

```c
static uint64_t uStack_88_4_4_ = 0;     // Declared as uint64_t fragment
...
uStack_88 = ...;                        // Used as raw pointer-sized value
pppppppppppuVar55 = (ulonglong ***)...(uintptr_t)uStack_88;  // Cast as pointer
```

Pattern shows:
1. Static declarations with fragment suffixes (line 2227): `uStack_88_4_4_`
2. Usage as full variable without suffix (line 7594): `uStack_88`
3. Implicit assumption: assignment to fragment syncs whole variable

### Why This is Engine Bug
1. **Fragment mismatch**: Declaration `uStack_88_4_4_` (bytes 4-4) vs use of `uStack_88` (full width)
2. **Type erasure**: Original undefined8/pointer distinction lost in fragment split
3. **Compiler error**: C doesn't allow bare fragment names; uStack_88 is undefined
4. **Stack layout**: Ghidra splits overlapping stack vars but loses unification logic

### Pattern & Fix

Detect pattern:
```
  static uint64_t (u[A-Za-z]*_[0-9a-f]+)_(\d+)_(\d+)_ = 0;  // Line 2227
  ...
  ([u]?Stack_\d+) = ...;  // Line 7594 - BARE usage without suffix
```

Fix:
1. After declaring static fragments, emit union:
   ```c
   union { 
     uint64_t uStack_88; 
     struct { uint8_t uStack_88_4_4_; } parts; 
   } uStack_88_union;
   ```

2. OR: Replace bare uStack_88 with `((uint64_t)uStack_88_4_4_)` or GHIDRA_U64(...) cast

3. **Safer approach (less invasive)**:
   - When fragment declared: also declare bare variable as `volatile uint64_t uStack_88 = 0;`
   - Maintains Ghidra's fragment semantics while unifying symbol
   - Compiler treats volatile as opaque, prevents false optimizations

### Reusability
- Applies to all u*Stack_*_X_Y_ patterns
- Applies to local_*_X_Y_ patterns
- Works regardless of binary size or function count
- Safe: doesn't change semantics, only makes implicit overlap explicit

### Complexity: LOW-MEDIUM | Confidence: MEDIUM-HIGH | Impact: LOW-MEDIUM

---

## IMPLEMENTATION ROADMAP

### Patch Order (Dependency-Based)
1. **Priority #1 first** (undeclared split locals): Must run before type extraction
2. **Priority #3 second** (fragment unions): Depends on #1 for correct symbol resolution
3. **Priority #2 last** (param widening): Uses corrected type info from #1 & #3

### Code Location in recompilation_engine.py
- **#1**: Insert at line 1055 (after _normalize_generated_c_semantics ends, before _normalize_pointer_integer_assignments)
- **#2**: Extend lines 1250-1256 in _relax_mismatched_pointer_prototypes
- **#3**: Insert at line 1100 (in _extract_declared_variable_types post-processing)

### Test Validation
- Rerun hexyl reconstruction with patches applied
- Check stderr for:
  - Undeclared variable errors: GONE
  - undefined8* type mismatch: GONE
  - Fragment symbol errors: GONE
- Expect 10-15% reduction in compilation errors

---

## SUMMARY TABLE

| # | Issue | Pattern | Lines | Complexity | Engine Bug? |
|---|-------|---------|-------|----------|-----------|
| 1 | Undeclared split locals | _local_228 = GHIDRA_U128(0x0) | 9912, 11634 | LOW | YES - Ghidra overlapping var split |
| 2 | undefined8* param mismatch | undefined8 *param_2 vs &pointer_local | 2682, 2596 | MED | YES - Ghidra param type inference |
| 3 | Fragment locals unification | uStack_88_4_4_ decl vs uStack_88 use | 2227, 7594 | MED | YES - Ghidra split-range tracking |

**Cumulative Expected Impact**: 15-25% compilation error reduction on hexyl binary

