"""
YARA Rule Generator for REVENG

Automatically generates YARA detection rules from analyzed binaries.
Includes string extraction, byte pattern identification, and rule optimization.
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
from collections import Counter

logger = logging.getLogger(__name__)


@dataclass
class YARARule:
    """YARA rule representation"""
    rule_name: str
    description: str
    author: str
    date: str
    reference: str
    hash: str
    strings: List[Tuple[str, str, str]]  # (var_name, value, modifiers)
    byte_patterns: List[Tuple[str, str]]  # (var_name, hex_pattern)
    condition: str
    metadata: Dict[str, str]
    tags: List[str]

    def to_yara(self) -> str:
        """Convert to YARA rule format"""
        rule = f"rule {self.rule_name}"

        # Add tags
        if self.tags:
            rule += f" : {' '.join(self.tags)}"

        rule += "\n{\n"

        # Metadata section
        rule += "    meta:\n"
        rule += f'        description = "{self.description}"\n'
        rule += f'        author = "{self.author}"\n'
        rule += f'        date = "{self.date}"\n'
        rule += f'        hash = "{self.hash}"\n'

        if self.reference:
            rule += f'        reference = "{self.reference}"\n'

        for key, value in self.metadata.items():
            rule += f'        {key} = "{value}"\n'

        # Strings section
        if self.strings or self.byte_patterns:
            rule += "\n    strings:\n"

            for var_name, value, modifiers in self.strings:
                mod_str = f" {modifiers}" if modifiers else ""
                rule += f'        ${var_name} = "{value}"{mod_str}\n'

            for var_name, hex_pattern in self.byte_patterns:
                rule += f'        ${var_name} = {{ {hex_pattern} }}\n'

        # Condition section
        rule += f"\n    condition:\n"
        for line in self.condition.split('\n'):
            rule += f"        {line}\n"

        rule += "}\n"
        return rule


class YARAGenerator:
    """
    Automatic YARA rule generator from binary analysis.

    Extracts unique strings, byte patterns, and creates optimized
    detection rules for malware samples.
    """

    def __init__(self, author: str = "REVENG Auto-Generator"):
        """
        Initialize YARA generator.

        Args:
            author: Author name to include in generated rules
        """
        self.author = author
        logger.info("YARA generator initialized")

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def extract_strings(
        self,
        file_path: str,
        min_length: int = 8,
        max_strings: int = 50
    ) -> List[str]:
        """
        Extract printable strings from binary.

        Args:
            file_path: Path to binary file
            min_length: Minimum string length
            max_strings: Maximum number of strings to extract

        Returns:
            List of extracted strings
        """
        strings = []

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Extract ASCII strings
            ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
            ascii_strings = re.findall(ascii_pattern, data)
            strings.extend([s.decode('ascii') for s in ascii_strings])

            # Extract Unicode strings
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
            unicode_strings = re.findall(unicode_pattern, data)
            strings.extend([s.decode('utf-16le', errors='ignore') for s in unicode_strings])

        except Exception as e:
            logger.error(f"Failed to extract strings: {e}")

        return strings[:max_strings]

    def find_unique_strings(
        self,
        strings: List[str],
        analysis_results: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Find unique/distinctive strings suitable for YARA rules.

        Args:
            strings: List of all strings
            analysis_results: Optional REVENG analysis results for context

        Returns:
            List of unique strings
        """
        unique = []

        # Common strings to exclude (too generic)
        exclude_patterns = [
            r'^[A-Z]:\\',  # Windows paths
            r'^C:\\Windows',
            r'^[a-z]+\.dll$',  # Common DLL names
            r'^kernel32$',
            r'^user32$',
            r'^\d+$',  # Pure numbers
            r'^[0-9a-f]{32,}$',  # Long hex strings
        ]

        # Look for interesting patterns
        interesting_patterns = [
            r'https?://[^\s]+',  # URLs
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Emails
            r'\\\\[^\\]+\\[^\\]+',  # UNC paths
            r'SELECT .+ FROM',  # SQL queries
            r'cmd\.exe|powershell',  # Command execution
            r'reg add|reg delete',  # Registry modification
            r'mutex|event|pipe',  # Synchronization objects
        ]

        for string in strings:
            # Skip if matches exclude patterns
            if any(re.search(pattern, string, re.IGNORECASE) for pattern in exclude_patterns):
                continue

            # Prioritize interesting patterns
            if any(re.search(pattern, string, re.IGNORECASE) for pattern in interesting_patterns):
                unique.append(string)
                continue

            # Include strings with good entropy (likely unique identifiers)
            if len(string) >= 12 and self._calculate_entropy(string) > 3.5:
                unique.append(string)

        return unique[:20]  # Limit to 20 most unique strings

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of string"""
        if not string:
            return 0.0

        entropy = 0.0
        for char in set(string):
            prob = string.count(char) / len(string)
            if prob > 0:
                entropy -= prob * (prob ** 0.5)  # Simplified entropy

        return entropy

    def extract_byte_patterns(
        self,
        file_path: str,
        pattern_length: int = 16,
        max_patterns: int = 10
    ) -> List[str]:
        """
        Extract unique byte patterns from binary.

        Args:
            file_path: Path to binary file
            pattern_length: Length of byte patterns to extract
            max_patterns: Maximum number of patterns

        Returns:
            List of hex byte patterns
        """
        patterns = []

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Look for unique sequences in the binary
            # Focus on code section (skip header and data sections)
            if len(data) > 1024:
                data = data[1024:min(len(data), 100000)]  # Sample from middle

            # Extract patterns at regular intervals
            step = max(1, len(data) // (max_patterns * 10))

            for i in range(0, len(data) - pattern_length, step):
                chunk = data[i:i + pattern_length]

                # Skip null-filled or repeated byte patterns
                if len(set(chunk)) > pattern_length // 2:  # Good variety
                    hex_pattern = ' '.join(f'{b:02X}' for b in chunk)
                    patterns.append(hex_pattern)

                if len(patterns) >= max_patterns:
                    break

        except Exception as e:
            logger.error(f"Failed to extract byte patterns: {e}")

        return patterns

    def generate_rule(
        self,
        file_path: str,
        analysis_results: Optional[Dict[str, Any]] = None,
        rule_name: Optional[str] = None
    ) -> YARARule:
        """
        Generate YARA rule from binary file.

        Args:
            file_path: Path to binary file
            analysis_results: Optional REVENG analysis results for enhanced rule
            rule_name: Optional custom rule name

        Returns:
            Generated YARA rule
        """
        sha256 = self.calculate_file_hash(file_path)
        file_name = Path(file_path).name

        # Generate rule name
        if not rule_name:
            if analysis_results and analysis_results.get('family'):
                family = analysis_results['family'].replace(' ', '_').replace('-', '_')
                rule_name = f"REVENG_{family}_{sha256[:8]}"
            else:
                rule_name = f"REVENG_{file_name.replace('.', '_')}_{sha256[:8]}"

        # Sanitize rule name (YARA compatible)
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)

        # Extract strings
        all_strings = self.extract_strings(file_path)
        unique_strings = self.find_unique_strings(all_strings, analysis_results)

        # Extract byte patterns
        byte_patterns = self.extract_byte_patterns(file_path)

        # Build strings section
        strings = []
        for idx, string in enumerate(unique_strings):
            var_name = f"s{idx}"

            # Determine modifiers
            modifiers = "nocase wide ascii"  # Search for both ASCII and Unicode

            # Escape special characters
            escaped_string = string.replace('\\', '\\\\').replace('"', '\\"')

            strings.append((var_name, escaped_string, modifiers))

        # Build byte patterns section
        byte_pattern_vars = []
        for idx, pattern in enumerate(byte_patterns):
            var_name = f"b{idx}"
            byte_pattern_vars.append((var_name, pattern))

        # Build metadata
        metadata = {}
        if analysis_results:
            if analysis_results.get('family'):
                metadata['family'] = analysis_results['family']
            if analysis_results.get('classification'):
                metadata['classification'] = analysis_results['classification']
            if analysis_results.get('threat_score'):
                metadata['threat_score'] = str(analysis_results['threat_score'])

        # Build tags
        tags = []
        if analysis_results:
            if analysis_results.get('classification') == 'malware':
                tags.append('malware')
            if analysis_results.get('family'):
                tags.append(analysis_results['family'].lower().replace(' ', '_'))

        # Build condition
        string_count = len(strings)
        pattern_count = len(byte_pattern_vars)

        conditions = []

        # PE file check (common for Windows malware)
        conditions.append("uint16(0) == 0x5A4D")  # MZ header

        # String matches
        if string_count >= 3:
            conditions.append(f"3 of ($s*)")
        elif string_count >= 1:
            conditions.append(f"any of ($s*)")

        # Byte pattern matches
        if pattern_count >= 2:
            conditions.append(f"2 of ($b*)")
        elif pattern_count >= 1:
            conditions.append(f"any of ($b*)")

        # Combine with OR
        condition = " and\n".join([
            conditions[0],  # MZ header
            f"(\n    {' or\n    '.join(conditions[1:])}\n)" if len(conditions) > 1 else ""
        ])

        # Create description
        description = f"Auto-generated YARA rule for {file_name}"
        if analysis_results and analysis_results.get('family'):
            description = f"Detection rule for {analysis_results['family']}"

        # Create rule
        rule = YARARule(
            rule_name=rule_name,
            description=description,
            author=self.author,
            date=datetime.now().strftime("%Y-%m-%d"),
            reference="",
            hash=sha256,
            strings=strings,
            byte_patterns=byte_pattern_vars,
            condition=condition,
            metadata=metadata,
            tags=tags
        )

        logger.info(f"Generated YARA rule: {rule_name}")
        return rule

    def generate_from_analysis(
        self,
        analysis_results: Dict[str, Any],
        file_path: Optional[str] = None
    ) -> YARARule:
        """
        Generate YARA rule from REVENG analysis results.

        Args:
            analysis_results: REVENG analysis results
            file_path: Optional path to original binary

        Returns:
            Generated YARA rule
        """
        # If file path not provided, try to extract from results
        if not file_path:
            file_path = analysis_results.get('binary_path')

        if not file_path:
            raise ValueError("File path required for YARA rule generation")

        return self.generate_rule(file_path, analysis_results)

    def save_rule(self, rule: YARARule, output_path: str):
        """
        Save YARA rule to file.

        Args:
            rule: YARA rule to save
            output_path: Path to save rule
        """
        try:
            with open(output_path, 'w') as f:
                f.write(rule.to_yara())

            logger.info(f"Saved YARA rule to {output_path}")

        except Exception as e:
            logger.error(f"Failed to save YARA rule: {e}")
            raise

    def optimize_rule(self, rule: YARARule) -> YARARule:
        """
        Optimize YARA rule for better performance and accuracy.

        Args:
            rule: Rule to optimize

        Returns:
            Optimized rule
        """
        # Remove duplicate strings
        unique_strings = {}
        for var_name, value, modifiers in rule.strings:
            if value not in unique_strings.values():
                unique_strings[var_name] = value

        # Rebuild strings list
        optimized_strings = [
            (var_name, value, mods)
            for (var_name, value, mods) in rule.strings
            if value in unique_strings.values()
        ]

        rule.strings = optimized_strings

        logger.info(f"Optimized rule {rule.rule_name}: {len(optimized_strings)} unique strings")
        return rule


# Convenience function
def quick_generate(file_path: str, output_path: Optional[str] = None) -> YARARule:
    """
    Quick YARA rule generation from file.

    Args:
        file_path: Path to binary
        output_path: Optional path to save rule

    Returns:
        Generated YARA rule
    """
    generator = YARAGenerator()
    rule = generator.generate_rule(file_path)

    if output_path:
        generator.save_rule(rule, output_path)

    return rule
