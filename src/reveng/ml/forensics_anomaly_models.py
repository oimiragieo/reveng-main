"""Lightweight ML anomaly models for malware forensics workflows."""

import math
import threading
from dataclasses import dataclass
from typing import Any, ClassVar, Dict, Iterable, List, Mapping, Sequence

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ..core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MLAnomalyAssessment:
    """Normalized anomaly assessment returned by the forensics models."""

    score: float
    threshold: float
    exceeded: bool
    reasons: List[str]
    features: Dict[str, float]
    raw_decision_score: float


class _IsolationForestFeatureModel:
    """Shared feature-vector anomaly model backed by Isolation Forest."""

    _instances: ClassVar[
        Dict[type["_IsolationForestFeatureModel"], "_IsolationForestFeatureModel"]
    ] = {}
    _instance_lock: ClassVar[threading.Lock] = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Reuse one trained model instance per concrete model class."""
        if cls is _IsolationForestFeatureModel:
            return super().__new__(cls)

        cached_instance = cls._instances.get(cls)
        if cached_instance is not None:
            return cached_instance

        with cls._instance_lock:
            cached_instance = cls._instances.get(cls)
            if cached_instance is None:
                cached_instance = super().__new__(cls)
                cached_instance._initialized = False
                cls._instances[cls] = cached_instance

        return cached_instance

    def __init__(
        self,
        feature_names: Sequence[str],
        benign_samples: Sequence[Sequence[float]],
        threshold: float,
        reason_labels: Mapping[str, str],
    ):
        if getattr(self, "_initialized", False):
            return

        with self.__class__._instance_lock:
            if getattr(self, "_initialized", False):
                return

            self.feature_names = list(feature_names)
            self.threshold = threshold
            self.reason_labels = dict(reason_labels)
            self.pipeline = Pipeline(
                [
                    ("scaler", StandardScaler()),
                    (
                        "detector",
                        IsolationForest(
                            contamination=0.15,
                            n_estimators=200,
                            random_state=42,
                        ),
                    ),
                ]
            )
            training_samples = list(benign_samples)
            self.pipeline.fit(training_samples)
            self._feature_stats = self._build_feature_stats(training_samples)
            decision_scores = [
                float(score)
                for score in self.pipeline.decision_function(training_samples)
            ]
            self._decision_mean = sum(decision_scores) / len(decision_scores)
            decision_variance = sum(
                (score - self._decision_mean) ** 2 for score in decision_scores
            ) / len(decision_scores)
            self._decision_std = max(math.sqrt(decision_variance), 0.15)
            self._initialized = True

    def assess(self, features: Mapping[str, float]) -> MLAnomalyAssessment:
        """Score a feature mapping and return a normalized anomaly assessment."""
        normalized_features = {
            name: float(features.get(name, 0.0)) for name in self.feature_names
        }
        feature_vector = [normalized_features[name] for name in self.feature_names]
        raw_decision_score = float(self.pipeline.decision_function([feature_vector])[0])
        normalized_score = self._normalize_score(raw_decision_score)
        reasons = self._build_reasons(normalized_features, normalized_score)
        exceeded = normalized_score >= self.threshold

        if not exceeded:
            reasons = []

        if exceeded:
            reasons.insert(
                0,
                (
                    f"ML anomaly score {normalized_score:.2f} exceeded "
                    f"threshold {self.threshold:.2f}"
                ),
            )

        return MLAnomalyAssessment(
            score=normalized_score,
            threshold=self.threshold,
            exceeded=exceeded,
            reasons=reasons,
            features=normalized_features,
            raw_decision_score=raw_decision_score,
        )

    def _normalize_score(self, raw_decision_score: float) -> float:
        """Convert Isolation Forest decision scores into a stable 0-1 anomaly score."""
        deviation = (self._decision_mean - raw_decision_score) / self._decision_std
        return 1.0 / (1.0 + math.exp(-deviation))

    def _build_feature_stats(
        self, benign_samples: Sequence[Sequence[float]]
    ) -> Dict[str, Dict[str, float]]:
        stats: Dict[str, Dict[str, float]] = {}
        for index, name in enumerate(self.feature_names):
            values = [float(sample[index]) for sample in benign_samples]
            mean_value = sum(values) / len(values)
            variance = sum((value - mean_value) ** 2 for value in values) / len(values)
            stats[name] = {
                "mean": mean_value,
                "std": max(math.sqrt(variance), 0.1),
            }
        return stats

    def _build_reasons(
        self,
        normalized_features: Mapping[str, float],
        normalized_score: float,
    ) -> List[str]:
        significant_features: List[tuple[float, str]] = []

        for name, value in normalized_features.items():
            feature_stats = self._feature_stats[name]
            z_score = (value - feature_stats["mean"]) / feature_stats["std"]
            if z_score > 1.5:
                label = self.reason_labels.get(name, name.replace("_", " "))
                significant_features.append((z_score, label))

        significant_features.sort(reverse=True)
        reasons = [label for _, label in significant_features[:3]]

        if not reasons and normalized_score >= self.threshold:
            reasons.append("feature distribution diverged from benign baseline")

        return reasons


class BehavioralAnomalyModel(_IsolationForestFeatureModel):
    """ML anomaly model for behavioral monitor event streams."""

    def __init__(self):
        super().__init__(
            feature_names=[
                "total_events",
                "unique_operations",
                "unique_behavior_types",
                "high_ratio",
                "critical_ratio",
                "medium_ratio",
                "network_ratio",
                "process_ratio",
                "memory_ratio",
                "anti_analysis_ratio",
                "indicator_ratio",
                "target_diversity",
            ],
            benign_samples=[
                [1, 1, 1, 0.00, 0.00, 0.10, 0.00, 0.00, 0.00, 0.00, 0.00, 0.50],
                [2, 2, 1, 0.00, 0.00, 0.15, 0.00, 0.00, 0.00, 0.00, 0.05, 0.70],
                [3, 2, 2, 0.10, 0.00, 0.20, 0.00, 0.10, 0.00, 0.00, 0.05, 0.66],
                [4, 3, 2, 0.10, 0.00, 0.25, 0.05, 0.00, 0.00, 0.00, 0.08, 0.75],
                [5, 4, 3, 0.15, 0.00, 0.30, 0.10, 0.05, 0.00, 0.00, 0.10, 0.80],
                [6, 4, 3, 0.20, 0.05, 0.20, 0.10, 0.10, 0.05, 0.00, 0.10, 0.83],
            ],
            threshold=0.60,
            reason_labels={
                "high_ratio": "elevated high-severity behavior ratio",
                "critical_ratio": "critical behavior ratio spiked",
                "network_ratio": "network activity deviated from benign baseline",
                "process_ratio": "process-manipulation activity increased",
                "memory_ratio": "memory manipulation activity increased",
                "anti_analysis_ratio": "anti-analysis activity increased",
                "indicator_ratio": "known suspicious operations concentrated in event stream",
            },
        )

    def assess_events(
        self,
        events: Sequence[Any],
        suspicious_operations: Iterable[str],
    ) -> MLAnomalyAssessment:
        total_events = max(len(events), 1)
        suspicious_operation_set = {
            operation.lower() for operation in suspicious_operations if operation
        }

        def _ratio(predicate) -> float:
            return sum(1 for event in events if predicate(event)) / total_events

        features = {
            "total_events": float(len(events)),
            "unique_operations": float(
                len({getattr(event, "operation", "") for event in events})
            ),
            "unique_behavior_types": float(
                len(
                    {
                        getattr(getattr(event, "behavior_type", None), "value", None)
                        for event in events
                    }
                    - {None}
                )
            ),
            "high_ratio": _ratio(
                lambda event: getattr(getattr(event, "threat_level", None), "value", "")
                in {"high", "critical"}
            ),
            "critical_ratio": _ratio(
                lambda event: getattr(getattr(event, "threat_level", None), "value", "")
                == "critical"
            ),
            "medium_ratio": _ratio(
                lambda event: getattr(getattr(event, "threat_level", None), "value", "")
                == "medium"
            ),
            "network_ratio": _ratio(
                lambda event: getattr(getattr(event, "behavior_type", None), "value", "")
                == "network_operation"
            ),
            "process_ratio": _ratio(
                lambda event: getattr(getattr(event, "behavior_type", None), "value", "")
                == "process_operation"
            ),
            "memory_ratio": _ratio(
                lambda event: getattr(getattr(event, "behavior_type", None), "value", "")
                == "memory_operation"
            ),
            "anti_analysis_ratio": _ratio(
                lambda event: getattr(getattr(event, "behavior_type", None), "value", "")
                == "anti_analysis"
            ),
            "indicator_ratio": _ratio(
                lambda event: getattr(event, "operation", "").lower()
                in suspicious_operation_set
            ),
            "target_diversity": len(
                {getattr(event, "target", "") for event in events if getattr(event, "target", "")}
            )
            / total_events,
        }
        return self.assess(features)


class MemoryArtifactAnomalyModel(_IsolationForestFeatureModel):
    """ML anomaly model for extracted memory region artifacts."""

    def __init__(self):
        super().__init__(
            feature_names=[
                "size_kb",
                "entropy",
                "byte_diversity",
                "ascii_ratio",
                "null_ratio",
                "pattern_density",
                "is_executable",
                "is_writable",
                "is_readable",
            ],
            benign_samples=[
                [1.0, 3.2, 0.10, 0.85, 0.05, 0.00, 0.0, 0.0, 1.0],
                [4.0, 4.1, 0.15, 0.70, 0.10, 0.02, 0.0, 1.0, 1.0],
                [8.0, 5.0, 0.22, 0.55, 0.08, 0.02, 1.0, 0.0, 1.0],
                [16.0, 5.4, 0.28, 0.40, 0.05, 0.03, 1.0, 1.0, 1.0],
                [2.0, 2.5, 0.08, 0.90, 0.02, 0.00, 0.0, 0.0, 1.0],
                [12.0, 4.8, 0.18, 0.62, 0.06, 0.01, 0.0, 1.0, 1.0],
            ],
            threshold=0.63,
            reason_labels={
                "entropy": "region entropy is unusually high",
                "byte_diversity": "byte diversity deviated from benign memory",
                "pattern_density": "suspicious API and shellcode tokens were concentrated",
                "is_executable": "executable memory content deviated from baseline",
            },
        )

    def assess_region(
        self,
        region: Any,
        data: bytes,
        suspicious_patterns: Mapping[str, Sequence[bytes]],
    ) -> MLAnomalyAssessment:
        total_patterns = max(
            sum(len(patterns) for patterns in suspicious_patterns.values()), 1
        )
        matched_patterns = sum(
            1
            for patterns in suspicious_patterns.values()
            for pattern in patterns
            if pattern in data
        )
        features = {
            "size_kb": min(len(data) / 1024.0, 1024.0),
            "entropy": _calculate_entropy(data),
            "byte_diversity": len(set(data)) / 256.0 if data else 0.0,
            "ascii_ratio": _calculate_ascii_ratio(data),
            "null_ratio": (data.count(0) / len(data)) if data else 0.0,
            "pattern_density": matched_patterns / total_patterns,
            "is_executable": 1.0 if getattr(region, "is_executable", False) else 0.0,
            "is_writable": 1.0 if getattr(region, "is_writable", False) else 0.0,
            "is_readable": 1.0 if getattr(region, "is_readable", True) else 0.0,
        }
        return self.assess(features)


class MemoryProcessAnomalyModel(_IsolationForestFeatureModel):
    """ML anomaly model for suspicious process behavior inside memory analysis."""

    def __init__(self):
        super().__init__(
            feature_names=[
                "parent_is_root",
                "suspicious_token_density",
                "command_length",
                "module_count",
                "handle_count",
                "region_count",
                "environment_size",
            ],
            benign_samples=[
                [0.0, 0.00, 0.08, 5.0, 10.0, 6.0, 5.0],
                [0.0, 0.05, 0.10, 7.0, 14.0, 8.0, 6.0],
                [0.0, 0.00, 0.12, 4.0, 8.0, 5.0, 4.0],
                [0.0, 0.02, 0.15, 6.0, 12.0, 7.0, 6.0],
                [0.0, 0.00, 0.09, 8.0, 16.0, 9.0, 8.0],
                [0.0, 0.05, 0.11, 3.0, 6.0, 4.0, 3.0],
            ],
            threshold=0.60,
            reason_labels={
                "parent_is_root": "process started from an unusual root parent",
                "suspicious_token_density": "command line contains malware execution tokens",
                "command_length": "command line length deviated from benign process launches",
            },
        )

    def assess_process(self, process: Any) -> MLAnomalyAssessment:
        command_line = getattr(process, "command_line", "") or ""
        process_name = getattr(process, "process_name", "") or ""
        combined_text = f"{process_name} {command_line}".lower()
        suspicious_keywords = [
            "powershell",
            "cmd",
            "wscript",
            "cscript",
            "rundll32",
            "regsvr32",
            "mshta",
            "certutil",
            "bitsadmin",
            "wmic",
            "schtasks",
            "-enc",
            "encodedcommand",
            "inject",
            "remote",
        ]
        keyword_hits = sum(1 for keyword in suspicious_keywords if keyword in combined_text)
        features = {
            "parent_is_root": 1.0 if getattr(process, "parent_id", 0) == 0 else 0.0,
            "suspicious_token_density": min(keyword_hits / 4.0, 1.0),
            "command_length": min(len(command_line) / 200.0, 1.0),
            "module_count": float(len(getattr(process, "loaded_modules", []) or [])),
            "handle_count": float(len(getattr(process, "open_handles", []) or [])),
            "region_count": float(len(getattr(process, "memory_regions", []) or [])),
            "environment_size": float(len(getattr(process, "environment", {}) or {})),
        }
        return self.assess(features)


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte string."""
    if len(data) < 2:
        return 0.0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0.0
    data_length = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / data_length
        entropy -= probability * math.log2(probability)

    return entropy


def _calculate_ascii_ratio(data: bytes) -> float:
    """Estimate the printable ASCII ratio for a memory region."""
    if not data:
        return 0.0
    printable_count = sum(1 for byte in data if 32 <= byte <= 126)
    return printable_count / len(data)
