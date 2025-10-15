#!/usr/bin/env python3
"""
REVENG ProGuard Mapping File Parser
====================================

Parses ProGuard mapping files (mapping.txt) to recover original class/method names.

ProGuard mapping file format:
    original.package.ClassName -> a.b.c:
        int originalField -> a
        void originalMethod(String) -> a
        ...

This tool:
1. Parses mapping.txt files
2. Creates bidirectional mappings (obfuscated <-> original)
3. Applies mappings to decompiled code
4. Generates deobfuscated source
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ClassMapping:
    """Mapping for a single class"""
    original_name: str
    obfuscated_name: str
    field_mappings: Dict[str, str] = field(default_factory=dict)  # obfuscated -> original
    method_mappings: Dict[str, str] = field(default_factory=dict)  # obfuscated -> original


class ProGuardMapper:
    """
    Parse and apply ProGuard mapping files

    Recovers original names from obfuscated bytecode using mapping.txt
    """

    # Regex patterns for ProGuard mapping file
    CLASS_MAPPING_PATTERN = re.compile(r'^([^\s]+)\s+->\s+([^\s:]+):$')
    FIELD_MAPPING_PATTERN = re.compile(r'^\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)$')
    METHOD_MAPPING_PATTERN = re.compile(r'^\s+(?:\d+:\d+:)?([^\s]+)\s+([^\s(]+)\(([^)]*)\)(?::\d+(?::\d+)?)?\s+->\s+([^\s]+)$')

    def __init__(self, mapping_file: Optional[Path] = None):
        """
        Initialize ProGuard mapper

        Args:
            mapping_file: Path to ProGuard mapping.txt file
        """
        self.mapping_file = mapping_file
        self.class_mappings: Dict[str, ClassMapping] = {}
        self.reverse_class_mappings: Dict[str, str] = {}  # obfuscated -> original

        if mapping_file and mapping_file.exists():
            self.parse_mapping_file()

    def parse_mapping_file(self):
        """Parse ProGuard mapping.txt file"""
        if not self.mapping_file or not self.mapping_file.exists():
            logger.error(f"Mapping file not found: {self.mapping_file}")
            return

        logger.info(f"Parsing ProGuard mapping file: {self.mapping_file}")

        current_class = None

        with open(self.mapping_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip('\n')

                # Skip empty lines and comments
                if not line or line.strip().startswith('#'):
                    continue

                # Check for class mapping
                class_match = self.CLASS_MAPPING_PATTERN.match(line)
                if class_match:
                    original = class_match.group(1)
                    obfuscated = class_match.group(2)

                    current_class = ClassMapping(
                        original_name=original,
                        obfuscated_name=obfuscated
                    )

                    self.class_mappings[original] = current_class
                    self.reverse_class_mappings[obfuscated] = original

                    logger.debug(f"Class mapping: {original} -> {obfuscated}")
                    continue

                # Must be inside a class
                if not current_class:
                    logger.warning(f"Line {line_num}: Not in class context: {line}")
                    continue

                # Check for field mapping
                field_match = self.FIELD_MAPPING_PATTERN.match(line)
                if field_match:
                    field_type = field_match.group(1)
                    original_name = field_match.group(2)
                    obfuscated_name = field_match.group(3)

                    current_class.field_mappings[obfuscated_name] = original_name
                    logger.debug(f"  Field: {original_name} -> {obfuscated_name}")
                    continue

                # Check for method mapping
                method_match = self.METHOD_MAPPING_PATTERN.match(line)
                if method_match:
                    return_type = method_match.group(1)
                    original_name = method_match.group(2)
                    params = method_match.group(3)
                    obfuscated_name = method_match.group(4)

                    # Store method signature for disambiguation
                    method_key = f"{obfuscated_name}({params})"
                    current_class.method_mappings[method_key] = original_name

                    # Also store simple name (without params) as fallback
                    if obfuscated_name not in current_class.method_mappings:
                        current_class.method_mappings[obfuscated_name] = original_name

                    logger.debug(f"  Method: {original_name}({params}) -> {obfuscated_name}")
                    continue

                # Unknown line format
                logger.debug(f"Line {line_num}: Unrecognized format: {line}")

        logger.info(f"Parsed {len(self.class_mappings)} class mappings")

    def get_original_class_name(self, obfuscated: str) -> str:
        """Get original class name from obfuscated name"""
        return self.reverse_class_mappings.get(obfuscated, obfuscated)

    def get_original_field_name(self, class_name: str, obfuscated_field: str) -> str:
        """Get original field name"""
        # Try to find class mapping
        class_mapping = None

        # Try obfuscated class name
        if class_name in self.reverse_class_mappings:
            original_class = self.reverse_class_mappings[class_name]
            class_mapping = self.class_mappings.get(original_class)

        # Try original class name
        if not class_mapping:
            class_mapping = self.class_mappings.get(class_name)

        if class_mapping:
            return class_mapping.field_mappings.get(obfuscated_field, obfuscated_field)

        return obfuscated_field

    def get_original_method_name(self, class_name: str, obfuscated_method: str, params: Optional[str] = None) -> str:
        """Get original method name"""
        # Try to find class mapping
        class_mapping = None

        # Try obfuscated class name
        if class_name in self.reverse_class_mappings:
            original_class = self.reverse_class_mappings[class_name]
            class_mapping = self.class_mappings.get(original_class)

        # Try original class name
        if not class_mapping:
            class_mapping = self.class_mappings.get(class_name)

        if class_mapping:
            # Try with params first (more specific)
            if params:
                method_key = f"{obfuscated_method}({params})"
                if method_key in class_mapping.method_mappings:
                    return class_mapping.method_mappings[method_key]

            # Fallback to simple name
            return class_mapping.method_mappings.get(obfuscated_method, obfuscated_method)

        return obfuscated_method

    def deobfuscate_java_source(self, java_source: str, obfuscated_class_name: str) -> str:
        """
        Deobfuscate Java source code using mapping

        Args:
            java_source: Obfuscated Java source code
            obfuscated_class_name: The obfuscated class name

        Returns:
            Deobfuscated source code
        """
        # Get original class name
        original_class_name = self.get_original_class_name(obfuscated_class_name)

        # Start with source
        deobfuscated = java_source

        # Replace class name
        if original_class_name != obfuscated_class_name:
            # Replace class declaration
            deobfuscated = re.sub(
                rf'\bclass\s+{re.escape(obfuscated_class_name)}\b',
                f'class {original_class_name}',
                deobfuscated
            )

        # Get class mapping
        class_mapping = self.class_mappings.get(original_class_name)
        if not class_mapping:
            logger.warning(f"No mapping found for class: {original_class_name}")
            return deobfuscated

        # Replace field names
        for obfuscated_field, original_field in class_mapping.field_mappings.items():
            # Replace field declarations and usages
            deobfuscated = re.sub(
                rf'\b{re.escape(obfuscated_field)}\b',
                original_field,
                deobfuscated
            )

        # Replace method names
        for obfuscated_method, original_method in class_mapping.method_mappings.items():
            # Remove params if present (we just want method name)
            if '(' in obfuscated_method:
                obfuscated_method = obfuscated_method.split('(')[0]

            # Replace method declarations and calls
            deobfuscated = re.sub(
                rf'\b{re.escape(obfuscated_method)}\b',
                original_method,
                deobfuscated
            )

        return deobfuscated

    def generate_report(self) -> Dict:
        """Generate mapping statistics report"""
        total_fields = sum(len(cm.field_mappings) for cm in self.class_mappings.values())
        total_methods = sum(len(cm.method_mappings) for cm in self.class_mappings.values())

        return {
            'total_classes': len(self.class_mappings),
            'total_fields': total_fields,
            'total_methods': total_methods,
            'classes': [
                {
                    'original': cm.original_name,
                    'obfuscated': cm.obfuscated_name,
                    'fields': len(cm.field_mappings),
                    'methods': len(cm.method_mappings)
                }
                for cm in self.class_mappings.values()
            ]
        }


def main():
    """Test ProGuard mapper"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='REVENG ProGuard Mapping Parser')
    parser.add_argument('mapping_file', help='Path to ProGuard mapping.txt')
    parser.add_argument('--java-file', help='Java source file to deobfuscate')
    parser.add_argument('--class-name', help='Obfuscated class name')
    parser.add_argument('--report', action='store_true', help='Generate mapping report')
    parser.add_argument('-o', '--output', help='Output file')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Parse mapping
    mapper = ProGuardMapper(Path(args.mapping_file))

    if args.report:
        # Generate report
        report = mapper.generate_report()

        print("\n=== ProGuard Mapping Report ===")
        print(f"Total Classes: {report['total_classes']}")
        print(f"Total Fields: {report['total_fields']}")
        print(f"Total Methods: {report['total_methods']}")

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\nSaved report to: {args.output}")

    elif args.java_file and args.class_name:
        # Deobfuscate Java file
        with open(args.java_file, 'r', encoding='utf-8') as f:
            java_source = f.read()

        deobfuscated = mapper.deobfuscate_java_source(java_source, args.class_name)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(deobfuscated)
            print(f"Deobfuscated source saved to: {args.output}")
        else:
            print("\n=== Deobfuscated Source ===")
            print(deobfuscated)

    else:
        # Just show summary
        print(f"\nParsed {len(mapper.class_mappings)} class mappings")
        print(f"Use --report for detailed statistics")
        print(f"Use --java-file and --class-name to deobfuscate source")


if __name__ == '__main__':
    main()
