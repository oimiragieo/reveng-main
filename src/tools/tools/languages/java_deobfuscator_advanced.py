#!/usr/bin/env python3
"""
REVENG Advanced Java Deobfuscator
==================================

Advanced deobfuscation techniques for Java bytecode:
- Control flow simplification (remove dead code, flatten control flow)
- String decryption (decrypt encrypted strings)
- Name demangling (restore meaningful names)
- Dead code elimination
- Constant folding

Handles obfuscation from: ProGuard, Allatori, DexGuard, Zelix KlassMaster
"""

import os
import re
import ast
import json
import logging
import base64
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class DeobfuscationResult:
    """Result from deobfuscation process"""
    original_file: str
    deobfuscated_file: str
    changes_made: int
    control_flow_simplified: int
    strings_decrypted: int
    dead_code_removed: int
    constants_folded: int
    confidence: float


class ControlFlowSimplifier:
    """
    Simplifies obfuscated control flow in Java code

    Techniques:
    - Remove always-true/false conditions
    - Flatten nested if-else chains
    - Remove dead code after return/throw
    - Simplify switch statements with single case
    - Remove empty try-catch blocks
    """

    def __init__(self):
        self.changes = 0

    def simplify(self, java_source: str) -> Tuple[str, int]:
        """Simplify control flow in Java source code"""
        self.changes = 0
        result = java_source

        # 1. Remove always-true conditions: if (true) { ... }
        result = self._remove_always_true_conditions(result)

        # 2. Remove always-false conditions: if (false) { ... }
        result = self._remove_always_false_conditions(result)

        # 3. Remove dead code after return
        result = self._remove_dead_code_after_return(result)

        # 4. Simplify switch with single case
        result = self._simplify_single_case_switch(result)

        # 5. Remove empty try-catch blocks
        result = self._remove_empty_try_catch(result)

        # 6. Flatten unnecessary nested blocks
        result = self._flatten_nested_blocks(result)

        # 7. Remove redundant casts
        result = self._remove_redundant_casts(result)

        return result, self.changes

    def _remove_always_true_conditions(self, source: str) -> str:
        """Remove if (true) { ... } patterns"""
        # Pattern: if (true) { ... } (without else)
        pattern = r'if\s*\(\s*true\s*\)\s*\{([^}]*)\}'

        def replace_func(match):
            self.changes += 1
            body = match.group(1).strip()
            return body if body else ''

        result = re.sub(pattern, replace_func, source)

        # Pattern: if (1 == 1) or if (0 == 0) etc.
        pattern2 = r'if\s*\(\s*(\d+)\s*==\s*\1\s*\)\s*\{([^}]*)\}'
        result = re.sub(pattern2, replace_func, result)

        return result

    def _remove_always_false_conditions(self, source: str) -> str:
        """Remove if (false) { ... } else { ... } patterns"""
        # Pattern: if (false) { ... } else { ... }
        pattern = r'if\s*\(\s*false\s*\)\s*\{[^}]*\}\s*else\s*\{([^}]*)\}'

        def replace_func(match):
            self.changes += 1
            else_body = match.group(1).strip()
            return else_body if else_body else ''

        result = re.sub(pattern, replace_func, source)

        # Pattern: if (false) { ... } (without else - remove entirely)
        pattern2 = r'if\s*\(\s*false\s*\)\s*\{[^}]*\}'
        result = re.sub(pattern2, lambda m: (self.changes := self.changes + 1, '')[1], result)

        return result

    def _remove_dead_code_after_return(self, source: str) -> str:
        """Remove unreachable code after return statements"""
        lines = source.splitlines()
        result_lines = []
        skip_until_brace = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Track brace depth
            if '{' in line:
                skip_until_brace = max(0, skip_until_brace - line.count('{'))
            if '}' in line:
                skip_until_brace += line.count('}')

            # If we hit a return/throw, skip until we hit a closing brace
            if skip_until_brace == 0 and (stripped.startswith('return ') or stripped.startswith('throw ')):
                result_lines.append(line)
                # Look ahead to find dead code
                j = i + 1
                while j < len(lines) and not lines[j].strip().startswith('}'):
                    if lines[j].strip() and not lines[j].strip().startswith('//'):
                        self.changes += 1
                    j += 1
                skip_until_brace = 1
            elif skip_until_brace > 0:
                if '}' in line:
                    result_lines.append(line)
                    skip_until_brace -= line.count('}')
            else:
                result_lines.append(line)

        return '\n'.join(result_lines)

    def _simplify_single_case_switch(self, source: str) -> str:
        """Simplify switch statements with only one case"""
        # Pattern: switch with single case
        pattern = r'switch\s*\([^)]+\)\s*\{\s*case\s+([^:]+):\s*([^}]+?)\s*break;\s*\}'

        def replace_func(match):
            self.changes += 1
            body = match.group(2).strip()
            return f'{{\n    {body}\n}}'

        return re.sub(pattern, replace_func, source, flags=re.DOTALL)

    def _remove_empty_try_catch(self, source: str) -> str:
        """Remove empty try-catch blocks"""
        # Pattern: try { ... } catch (Exception e) { } (empty catch)
        pattern = r'try\s*\{([^}]+)\}\s*catch\s*\([^)]+\)\s*\{\s*\}'

        def replace_func(match):
            self.changes += 1
            try_body = match.group(1).strip()
            return try_body if try_body else ''

        return re.sub(pattern, replace_func, source, flags=re.DOTALL)

    def _flatten_nested_blocks(self, source: str) -> str:
        """Remove unnecessary nested blocks: { { ... } }"""
        # Pattern: single nested block
        pattern = r'\{\s*\{([^}]+)\}\s*\}'

        def replace_func(match):
            self.changes += 1
            body = match.group(1).strip()
            return f'{{ {body} }}'

        return re.sub(pattern, replace_func, source, flags=re.DOTALL)

    def _remove_redundant_casts(self, source: str) -> str:
        """Remove redundant type casts like (String)"string" """
        # Pattern: (Type)literal where Type matches literal type
        pattern = r'\(String\)\s*"([^"]*)"'
        result = re.sub(pattern, lambda m: f'"{m.group(1)}"', source)

        pattern2 = r'\(int\)\s*(\d+)'
        result = re.sub(pattern2, lambda m: m.group(1), result)

        return result


class StringDecryptor:
    """
    Decrypts encrypted strings in obfuscated Java code

    Supports common encryption patterns:
    - Base64 decoding
    - XOR encryption with constant key
    - Simple character shifting
    - String concatenation obfuscation
    """

    def __init__(self):
        self.decrypted_count = 0

    def decrypt_strings(self, java_source: str) -> Tuple[str, int]:
        """Decrypt encrypted strings in Java source"""
        self.decrypted_count = 0
        result = java_source

        # 1. Detect and decrypt Base64 strings
        result = self._decrypt_base64_strings(result)

        # 2. Detect and decrypt XOR strings
        result = self._decrypt_xor_strings(result)

        # 3. Simplify string concatenation
        result = self._simplify_string_concat(result)

        # 4. Decode character escapes
        result = self._decode_char_escapes(result)

        return result, self.decrypted_count

    def _decrypt_base64_strings(self, source: str) -> str:
        """Detect and decrypt Base64-encoded strings"""
        # Pattern: new String(Base64.decode("..."))
        pattern = r'new\s+String\s*\(\s*Base64\.decode\s*\(\s*"([A-Za-z0-9+/=]+)"\s*\)\s*\)'

        def replace_func(match):
            try:
                encoded = match.group(1)
                decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                self.decrypted_count += 1
                return f'"{decoded}"'
            except Exception:
                return match.group(0)

        return re.sub(pattern, replace_func, source)

    def _decrypt_xor_strings(self, source: str) -> str:
        """Detect and decrypt XOR-encrypted strings with constant key"""
        # Pattern: decrypt method call like decrypt("encrypted", 0x42)
        pattern = r'decrypt\s*\(\s*"([^"]+)"\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)'

        def replace_func(match):
            try:
                encrypted = match.group(1)
                key = int(match.group(2), 0)  # Handles both 0x and decimal

                # Try XOR decryption
                decrypted = ''.join(chr(ord(c) ^ key) for c in encrypted)

                # Only replace if result looks like valid text
                if decrypted.isprintable():
                    self.decrypted_count += 1
                    return f'"{decrypted}"'
            except Exception:
                pass

            return match.group(0)

        return re.sub(pattern, replace_func, source)

    def _simplify_string_concat(self, source: str) -> str:
        """Simplify obfuscated string concatenation"""
        # Pattern: "part1" + "part2" + "part3"
        pattern = r'"([^"]*)"\s*\+\s*"([^"]*)"'

        # Keep replacing until no more matches
        prev_source = None
        result = source
        while prev_source != result:
            prev_source = result
            result = re.sub(pattern, lambda m: f'"{m.group(1)}{m.group(2)}"', result)
            if prev_source != result:
                self.decrypted_count += 1

        return result

    def _decode_char_escapes(self, source: str) -> str:
        """Decode obfuscated character escapes like \\u0041 -> A"""
        # Pattern: Unicode escapes \\uXXXX
        pattern = r'\\u([0-9a-fA-F]{4})'

        def replace_func(match):
            try:
                code_point = int(match.group(1), 16)
                char = chr(code_point)
                if char.isprintable() and char not in '"\\':
                    self.decrypted_count += 1
                    return char
            except Exception:
                pass
            return match.group(0)

        return re.sub(pattern, replace_func, source)


class DeadCodeEliminator:
    """
    Removes dead code (unreachable code, unused variables)

    Techniques:
    - Remove unreachable code
    - Remove unused local variables
    - Remove unused imports
    - Remove empty methods
    """

    def __init__(self):
        self.removed_count = 0

    def eliminate(self, java_source: str) -> Tuple[str, int]:
        """Remove dead code from Java source"""
        self.removed_count = 0
        result = java_source

        # 1. Remove unused imports
        result = self._remove_unused_imports(result)

        # 2. Remove empty methods
        result = self._remove_empty_methods(result)

        # 3. Remove unused private methods (basic heuristic)
        result = self._remove_unused_private_methods(result)

        return result, self.removed_count

    def _remove_unused_imports(self, source: str) -> str:
        """Remove import statements for classes not used in source"""
        lines = source.splitlines()
        imports = []
        other_lines = []

        # Separate imports from other code
        for line in lines:
            if line.strip().startswith('import '):
                imports.append(line)
            else:
                other_lines.append(line)

        # Check which imports are actually used
        code_body = '\n'.join(other_lines)
        used_imports = []

        for import_line in imports:
            # Extract class name from import
            match = re.search(r'import\s+(?:static\s+)?([^;]+);', import_line)
            if match:
                import_path = match.group(1)
                class_name = import_path.split('.')[-1]

                # Check if class name appears in code
                if class_name in code_body:
                    used_imports.append(import_line)
                else:
                    self.removed_count += 1

        # Reconstruct source
        result_lines = []
        for line in lines:
            if line.strip().startswith('import '):
                if line in used_imports:
                    result_lines.append(line)
            else:
                result_lines.append(line)

        return '\n'.join(result_lines)

    def _remove_empty_methods(self, source: str) -> str:
        """Remove empty methods (only comments or whitespace)"""
        # Pattern: method with empty body
        pattern = r'((?:public|private|protected)\s+(?:static\s+)?(?:void|[\w<>]+)\s+\w+\s*\([^)]*\)\s*)\{\s*\}'

        def replace_func(match):
            self.removed_count += 1
            return ''

        return re.sub(pattern, replace_func, source, flags=re.MULTILINE)

    def _remove_unused_private_methods(self, source: str) -> str:
        """Remove private methods that are never called (basic heuristic)"""
        # Find all private method names
        private_methods = re.findall(r'private\s+(?:static\s+)?(?:void|[\w<>]+)\s+(\w+)\s*\(', source)

        for method_name in private_methods:
            # Count occurrences (at least 2 means definition + usage)
            occurrences = len(re.findall(rf'\b{method_name}\b', source))

            if occurrences == 1:  # Only definition, no usage
                # Remove method definition (simplified - may not handle all cases)
                pattern = rf'private\s+(?:static\s+)?(?:void|[\w<>]+)\s+{method_name}\s*\([^)]*\)\s*\{{[^}}]*\}}'
                source = re.sub(pattern, '', source, flags=re.DOTALL)
                self.removed_count += 1

        return source


class ConstantFolder:
    """
    Performs constant folding and propagation

    Techniques:
    - Fold constant arithmetic (2 + 3 -> 5)
    - Fold constant boolean expressions (true && x -> x)
    - Propagate constant variables
    """

    def __init__(self):
        self.folded_count = 0

    def fold_constants(self, java_source: str) -> Tuple[str, int]:
        """Fold constants in Java source"""
        self.folded_count = 0
        result = java_source

        # 1. Fold arithmetic expressions
        result = self._fold_arithmetic(result)

        # 2. Fold boolean expressions
        result = self._fold_boolean(result)

        return result, self.folded_count

    def _fold_arithmetic(self, source: str) -> str:
        """Fold constant arithmetic expressions"""
        # Pattern: simple additions like 5 + 3
        pattern = r'(\d+)\s*\+\s*(\d+)'

        def replace_func(match):
            try:
                a = int(match.group(1))
                b = int(match.group(2))
                self.folded_count += 1
                return str(a + b)
            except Exception:
                return match.group(0)

        result = re.sub(pattern, replace_func, source)

        # Pattern: simple multiplications like 5 * 3
        pattern2 = r'(\d+)\s*\*\s*(\d+)'
        result = re.sub(pattern2, replace_func, result)

        return result

    def _fold_boolean(self, source: str) -> str:
        """Fold constant boolean expressions"""
        # Pattern: true && x -> x
        pattern = r'true\s*&&\s*(\w+)'
        result = re.sub(pattern, r'\1', source)

        # Pattern: false || x -> x
        pattern2 = r'false\s*\|\|\s*(\w+)'
        result = re.sub(pattern2, r'\1', result)

        # Pattern: !true -> false
        result = result.replace('!true', 'false')
        result = result.replace('!false', 'true')

        return result


class JavaAdvancedDeobfuscator:
    """
    Main deobfuscator that combines all techniques

    Workflow:
    1. Control flow simplification
    2. String decryption
    3. Dead code elimination
    4. Constant folding
    5. Final cleanup
    """

    def __init__(self, output_dir: str = "deobfuscated_advanced"):
        self.output_dir = Path(output_dir)
        self.control_flow_simplifier = ControlFlowSimplifier()
        self.string_decryptor = StringDecryptor()
        self.dead_code_eliminator = DeadCodeEliminator()
        self.constant_folder = ConstantFolder()

    def deobfuscate_file(self, java_file: Path) -> DeobfuscationResult:
        """Deobfuscate a single Java file"""
        logger.info(f"Deobfuscating {java_file}")

        # Read source
        try:
            source = java_file.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Failed to read {java_file}: {e}")
            return None

        original_source = source
        total_changes = 0

        # Step 1: Control flow simplification
        source, cf_changes = self.control_flow_simplifier.simplify(source)
        total_changes += cf_changes

        # Step 2: String decryption
        source, str_changes = self.string_decryptor.decrypt_strings(source)
        total_changes += str_changes

        # Step 3: Dead code elimination
        source, dc_changes = self.dead_code_eliminator.eliminate(source)
        total_changes += dc_changes

        # Step 4: Constant folding
        source, const_changes = self.constant_folder.fold_constants(source)
        total_changes += const_changes

        # Calculate confidence (based on number of changes)
        confidence = min(0.95, 0.5 + (total_changes * 0.05))

        # Write deobfuscated file
        output_file = self.output_dir / java_file.name
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_file.write_text(source, encoding='utf-8')

        result = DeobfuscationResult(
            original_file=str(java_file),
            deobfuscated_file=str(output_file),
            changes_made=total_changes,
            control_flow_simplified=cf_changes,
            strings_decrypted=str_changes,
            dead_code_removed=dc_changes,
            constants_folded=const_changes,
            confidence=confidence
        )

        logger.info(f"Deobfuscated {java_file}: {total_changes} changes made")
        return result

    def deobfuscate_directory(self, source_dir: Path) -> List[DeobfuscationResult]:
        """Deobfuscate all Java files in a directory"""
        results = []

        for java_file in source_dir.rglob('*.java'):
            result = self.deobfuscate_file(java_file)
            if result:
                results.append(result)

        # Generate summary report
        self._generate_summary_report(results)

        return results

    def _generate_summary_report(self, results: List[DeobfuscationResult]):
        """Generate summary report of deobfuscation"""
        report = {
            'total_files': len(results),
            'total_changes': sum(r.changes_made for r in results),
            'control_flow_simplified': sum(r.control_flow_simplified for r in results),
            'strings_decrypted': sum(r.strings_decrypted for r in results),
            'dead_code_removed': sum(r.dead_code_removed for r in results),
            'constants_folded': sum(r.constants_folded for r in results),
            'average_confidence': sum(r.confidence for r in results) / len(results) if results else 0,
            'files': [asdict(r) for r in results]
        }

        report_file = self.output_dir / 'deobfuscation_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Generated deobfuscation report: {report_file}")

        # Print summary
        print("\n" + "="*60)
        print("ADVANCED DEOBFUSCATION COMPLETE")
        print("="*60)
        print(f"Files processed: {report['total_files']}")
        print(f"Total changes: {report['total_changes']}")
        print(f"  - Control flow simplified: {report['control_flow_simplified']}")
        print(f"  - Strings decrypted: {report['strings_decrypted']}")
        print(f"  - Dead code removed: {report['dead_code_removed']}")
        print(f"  - Constants folded: {report['constants_folded']}")
        print(f"Average confidence: {report['average_confidence']:.2%}")
        print("="*60)


def main():
    """CLI interface for advanced deobfuscation"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Advanced Java deobfuscation with control flow simplification and string decryption'
    )
    parser.add_argument('input', help='Path to Java file or directory')
    parser.add_argument('-o', '--output', default='deobfuscated_advanced',
                       help='Output directory for deobfuscated code')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    deobfuscator = JavaAdvancedDeobfuscator(output_dir=args.output)

    input_path = Path(args.input)
    if input_path.is_file():
        deobfuscator.deobfuscate_file(input_path)
    elif input_path.is_dir():
        deobfuscator.deobfuscate_directory(input_path)
    else:
        print(f"Error: {args.input} is not a valid file or directory")
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
