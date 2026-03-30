"""Built-in YARA scanning and malware classification support for REVENG."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from reveng.ml.forensics_anomaly_models import ForensicsAnomalyModel

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency handling
    pefile = None
    PEFILE_AVAILABLE = False

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency handling
    yara = None
    YARA_AVAILABLE = False


@dataclass
class YARAMatch:
    """Normalized YARA match result used across REVENG."""

    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[Tuple[int, str, bytes]]


class YARAScanner:
    """Scan binaries with built-in YARA signatures and lightweight ML heuristics."""

    BUILTIN_RULES_DIR = Path(__file__).with_name("yara_rules")
    _ASCII_MIN_LENGTH = 4
    _SUSPICIOUS_IMPORTS = {
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenA",
        "InternetOpenW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "HttpSendRequestA",
        "HttpSendRequestW",
        "WinHttpOpen",
        "WinHttpSendRequest",
        "CryptEncrypt",
        "BCryptEncrypt",
        "MiniDumpWriteDump",
        "GetAsyncKeyState",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
    }
    _INDICATOR_TOKENS = (
        "powershell",
        "downloadstring",
        "downloadfile",
        "vssadmin delete shadows",
        "your files are encrypted",
        "createremotethread",
        "writeprocessmemory",
        "virtualalloc",
        "minidumpwritedump",
        "getasynckeystate",
        "software\\microsoft\\windows\\currentversion\\run",
        "appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
        "bitcoin",
        ".onion",
    )

    def __init__(
        self,
        rules_path: Optional[str] = None,
        rules_dir: Optional[str] = None,
        rule_file: Optional[str] = None,
        match_timeout: int = 30,
    ):
        if not YARA_AVAILABLE:
            raise ImportError(
                "YARA scanner requires 'yara-python' package. Install with: pip install yara-python"
            )

        self.match_timeout = match_timeout
        self.builtin_rule_files = self._discover_rule_files(self.BUILTIN_RULES_DIR)
        self.builtin_rules = self._extract_rule_names(self.builtin_rule_files.values())
        self.active_rule_files: Dict[str, str] = {}
        self.rules = None
        self.load_rules(rules_path=rules_path, rules_dir=rules_dir, rule_file=rule_file)

    def load_rules(
        self,
        rules_path: Optional[str] = None,
        rules_dir: Optional[str] = None,
        rule_file: Optional[str] = None,
    ) -> None:
        """Load either built-in rules or a user-specified ruleset."""
        explicit_files = self._resolve_custom_rule_files(
            rules_path=rules_path,
            rules_dir=rules_dir,
            rule_file=rule_file,
        )
        self.active_rule_files = explicit_files or dict(self.builtin_rule_files)
        if not self.active_rule_files:
            raise ValueError("No YARA rules were found to compile")
        self.rules = yara.compile(filepaths=self.active_rule_files)

    def scan_file(self, file_path: str) -> List[YARAMatch]:
        """Scan a file using the currently loaded YARA rules."""
        if self.rules is None:
            return []
        matches = self.rules.match(filepath=file_path, timeout=self.match_timeout)
        return self._normalize_matches(matches)

    def scan_data(self, data: bytes) -> List[YARAMatch]:
        """Scan in-memory data using the currently loaded YARA rules."""
        if self.rules is None:
            return []
        matches = self.rules.match(data=data, timeout=self.match_timeout)
        return self._normalize_matches(matches)

    def classify_file(
        self,
        file_path: str,
        *,
        use_ollama_family_naming: bool = False,
    ) -> Dict[str, Any]:
        """Classify a binary using built-in YARA rules plus a static anomaly model."""
        del use_ollama_family_naming  # Ollama naming is handled by the MCP layer.

        matches = self.scan_file(file_path)
        features = self.extract_static_features(file_path)
        ml_assessment = ForensicsAnomalyModel().assess_binary_features(features)
        matched_rules = [match.rule_name for match in matches]
        family = self._infer_family(matches, ml_assessment, features)
        confidence = self._calculate_confidence(matches, ml_assessment, family)
        indicators = self._build_indicators(matches, ml_assessment, features)

        return {
            "family": family,
            "confidence": confidence,
            "matched_rules": matched_rules,
            "indicators": indicators,
            "yara_matches": [self._serialize_match(match) for match in matches],
            "ml_assessment": {
                "score": round(ml_assessment.score, 3),
                "threshold": round(ml_assessment.threshold, 3),
                "exceeded": ml_assessment.exceeded,
                "reasons": list(ml_assessment.reasons),
                "features": {key: round(value, 4) for key, value in ml_assessment.features.items()},
            },
            "feature_summary": {key: round(value, 4) for key, value in features.items()},
        }

    def enrich_analysis(
        self, analysis_results: Dict[str, Any], file_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Attach YARA results and static malware classification to analysis output."""
        enriched = dict(analysis_results)
        target_path = file_path or analysis_results.get("binary_path")
        if not target_path or not Path(target_path).exists():
            return enriched

        classification = self.classify_file(target_path, use_ollama_family_naming=False)
        enriched["yara_matches"] = classification["yara_matches"]
        enriched["malware_classification"] = {
            "family": classification["family"],
            "confidence": classification["confidence"],
            "matched_rules": classification["matched_rules"],
            "indicators": classification["indicators"],
        }

        threat_intel = dict(enriched.get("threat_intel") or {})
        threat_intel["yara_matches"] = classification["yara_matches"]
        threat_intel["malware_classification"] = enriched["malware_classification"]
        enriched["threat_intel"] = threat_intel
        return enriched

    def extract_static_features(self, file_path: str) -> Dict[str, float]:
        """Extract file entropy, imports, and section characteristics for ML scoring."""
        path = Path(file_path)
        data = path.read_bytes()
        features: Dict[str, float] = {
            "file_size_kb": min(len(data) / 1024.0, 51200.0),
            "entropy": self._calculate_entropy(data),
            "is_pe": 1.0 if data[:2] == b"MZ" else 0.0,
            "import_count": 0.0,
            "suspicious_import_ratio": 0.0,
            "section_count": 0.0,
            "executable_section_count": 0.0,
            "writable_executable_section_count": 0.0,
            "average_section_entropy": 0.0,
            "max_section_entropy": 0.0,
            "string_indicator_density": 0.0,
        }

        extracted_strings = self._extract_ascii_strings(data)
        indicator_hits = sum(
            1
            for extracted in extracted_strings
            for token in self._INDICATOR_TOKENS
            if token in extracted.lower()
        )
        features["string_indicator_density"] = indicator_hits / max(len(extracted_strings), 1)

        if not (PEFILE_AVAILABLE and features["is_pe"]):
            return features

        pe_instance = None
        try:
            pe_instance = pefile.PE(str(path), fast_load=True)
            if hasattr(pe_instance, "parse_data_directories"):
                pe_instance.parse_data_directories()

            imports: List[str] = []
            for entry in getattr(pe_instance, "DIRECTORY_ENTRY_IMPORT", []) or []:
                for imported_symbol in getattr(entry, "imports", []) or []:
                    if imported_symbol.name:
                        imports.append(imported_symbol.name.decode("utf-8", errors="ignore"))

            features["import_count"] = float(len(imports))
            if imports:
                suspicious_count = sum(
                    1 for imported_symbol in imports if imported_symbol in self._SUSPICIOUS_IMPORTS
                )
                features["suspicious_import_ratio"] = suspicious_count / len(imports)

            sections = list(getattr(pe_instance, "sections", []) or [])
            features["section_count"] = float(len(sections))
            if sections:
                execute_mask = 0x20000000
                write_mask = 0x80000000
                entropies: List[float] = []
                executable_sections = 0
                writable_executable_sections = 0
                for section in sections:
                    entropy = float(section.get_entropy())
                    entropies.append(entropy)
                    characteristics = int(getattr(section, "Characteristics", 0))
                    if characteristics & execute_mask:
                        executable_sections += 1
                    if characteristics & execute_mask and characteristics & write_mask:
                        writable_executable_sections += 1

                features["executable_section_count"] = float(executable_sections)
                features["writable_executable_section_count"] = float(writable_executable_sections)
                features["average_section_entropy"] = sum(entropies) / len(entropies)
                features["max_section_entropy"] = max(entropies)
        except Exception:
            return features
        finally:
            if pe_instance is not None:
                try:
                    pe_instance.close()
                except Exception:
                    pass

        return features

    def _discover_rule_files(self, directory: Path) -> Dict[str, str]:
        if not directory.exists():
            return {}
        return {rule_file.stem: str(rule_file) for rule_file in sorted(directory.glob("*.yar"))}

    def _resolve_custom_rule_files(
        self,
        *,
        rules_path: Optional[str],
        rules_dir: Optional[str],
        rule_file: Optional[str],
    ) -> Dict[str, str]:
        explicit_files: Dict[str, str] = {}
        candidate_paths = [rules_path, rules_dir, rule_file]
        for candidate in candidate_paths:
            if not candidate:
                continue
            path = Path(candidate)
            if not path.exists():
                raise ValueError(f"Invalid rules path: {candidate}")
            if path.is_file():
                explicit_files[path.stem] = str(path)
            else:
                explicit_files.update(self._discover_rule_files(path))
        return explicit_files

    def _extract_rule_names(self, rule_files: Iterable[str]) -> List[str]:
        rule_names: List[str] = []
        pattern = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)")
        for rule_file in rule_files:
            text = Path(rule_file).read_text(encoding="utf-8")
            rule_names.extend(pattern.findall(text))
        return rule_names

    def _normalize_matches(self, matches: Sequence[Any]) -> List[YARAMatch]:
        normalized_matches: List[YARAMatch] = []
        for match in matches:
            normalized_matches.append(
                YARAMatch(
                    rule_name=str(getattr(match, "rule", getattr(match, "rule_name", "unknown"))),
                    namespace=str(getattr(match, "namespace", "default")),
                    tags=list(getattr(match, "tags", [])),
                    meta=dict(getattr(match, "meta", {})),
                    strings=self._normalize_match_strings(getattr(match, "strings", [])),
                )
            )
        return normalized_matches

    def _normalize_match_strings(self, strings: Sequence[Any]) -> List[Tuple[int, str, bytes]]:
        normalized: List[Tuple[int, str, bytes]] = []
        for string_match in strings:
            if isinstance(string_match, tuple) and len(string_match) == 3:
                offset, identifier, data = string_match
                payload = (
                    data if isinstance(data, bytes) else str(data).encode("utf-8", errors="replace")
                )
                normalized.append((int(offset), str(identifier), payload))
                continue

            identifier = str(getattr(string_match, "identifier", "$match"))
            instances = getattr(string_match, "instances", None)
            if instances is not None:
                for instance in instances:
                    payload = getattr(instance, "matched_data", getattr(instance, "data", b""))
                    if isinstance(payload, str):
                        payload = payload.encode("utf-8", errors="replace")
                    normalized.append((int(getattr(instance, "offset", 0)), identifier, payload))
                continue

            payload = getattr(string_match, "matched_data", getattr(string_match, "data", b""))
            if isinstance(payload, str):
                payload = payload.encode("utf-8", errors="replace")
            normalized.append((int(getattr(string_match, "offset", 0)), identifier, payload))

        return normalized

    def _infer_family(
        self,
        matches: Sequence[YARAMatch],
        ml_assessment: Any,
        features: Mapping[str, float],
    ) -> str:
        family_votes: Counter[str] = Counter()
        category_votes: Counter[str] = Counter()

        for match in matches:
            family = str(match.meta.get("family", "")).strip()
            if family:
                family_votes[family] += 2

            categories = [str(match.meta.get("category", "")).strip()] + list(match.tags)
            for category in categories:
                normalized = category.lower().replace("_", " ").strip()
                if normalized in {
                    "ransomware",
                    "trojan",
                    "backdoor",
                    "loader",
                    "downloader",
                    "credential theft",
                    "shellcode",
                    "spyware",
                    "dropper",
                }:
                    category_votes[normalized] += 1

        if family_votes:
            return family_votes.most_common(1)[0][0]

        if category_votes:
            dominant_category = category_votes.most_common(1)[0][0]
            return f"Generic {dominant_category.title()}"

        if (
            features.get("writable_executable_section_count", 0.0) > 0
            and features.get("entropy", 0.0) >= 7.0
        ):
            return "Packed Loader"

        if features.get("suspicious_import_ratio", 0.0) >= 0.25:
            return "Generic Trojan"

        if ml_assessment.exceeded:
            return "Suspicious Binary"

        if features.get("is_pe", 0.0) > 0:
            return "Unknown PE Binary"

        return "Unknown Binary"

    def _calculate_confidence(
        self,
        matches: Sequence[YARAMatch],
        ml_assessment: Any,
        family: str,
    ) -> float:
        non_structural_matches = [
            match for match in matches if "structural" not in {tag.lower() for tag in match.tags}
        ]
        confidence = 0.05
        confidence += min(len(non_structural_matches) * 0.18, 0.54)
        confidence += min(ml_assessment.score * 0.30, 0.30)

        if family not in {"Unknown PE Binary", "Unknown Binary"}:
            confidence += 0.15
        if family == "Packed Loader":
            confidence += 0.10
        if any("eicar" in match.rule_name.lower() for match in matches):
            confidence = max(confidence, 0.99)
        if not non_structural_matches and not ml_assessment.exceeded:
            confidence = min(confidence, 0.35)

        return float(round(max(0.0, min(confidence, 1.0)), 3))

    def _build_indicators(
        self,
        matches: Sequence[YARAMatch],
        ml_assessment: Any,
        features: Mapping[str, float],
    ) -> List[str]:
        indicators: List[str] = []

        for match in matches:
            description = str(match.meta.get("description", "")).strip()
            if description:
                indicators.append(description)
            else:
                indicators.append(f"Matched YARA rule {match.rule_name}")

        if features.get("entropy", 0.0) >= 7.0:
            indicators.append(
                f"High file entropy ({features['entropy']:.2f}) suggests packing or encryption"
            )
        if features.get("writable_executable_section_count", 0.0) > 0:
            indicators.append("Writable and executable PE sections were detected")
        if features.get("suspicious_import_ratio", 0.0) >= 0.15:
            indicators.append("Import table contains a concentrated set of suspicious APIs")

        indicators.extend(ml_assessment.reasons)

        deduplicated: List[str] = []
        seen = set()
        for indicator in indicators:
            normalized = indicator.strip()
            if not normalized:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(normalized)
        return deduplicated[:10]

    def _serialize_match(self, match: YARAMatch) -> Dict[str, Any]:
        return {
            "rule": match.rule_name,
            "namespace": match.namespace,
            "tags": list(match.tags),
            "meta": dict(match.meta),
            "strings": [
                {
                    "offset": offset,
                    "identifier": identifier,
                    "data_text": data.decode("utf-8", errors="replace"),
                    "data_hex": data.hex(),
                }
                for offset, identifier, data in match.strings
            ],
        }

    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        current = bytearray()
        strings: List[str] = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(byte)
                continue
            if len(current) >= self._ASCII_MIN_LENGTH:
                strings.append(current.decode("ascii", errors="ignore"))
            current.clear()

        if len(current) >= self._ASCII_MIN_LENGTH:
            strings.append(current.decode("ascii", errors="ignore"))
        return strings

    def _calculate_entropy(self, data: bytes) -> float:
        if len(data) < 2:
            return 0.0

        counts = [0] * 256
        for byte in data:
            counts[byte] += 1

        entropy = 0.0
        data_length = len(data)
        for count in counts:
            if count == 0:
                continue
            probability = count / data_length
            entropy -= probability * math.log2(probability)
        return entropy
