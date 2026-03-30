"""
Cost Tracking and Analytics
============================

Track token usage, API costs, and generate billing reports.
"""

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .types import CostReport, UsageMetrics

# Model pricing (as of 2024-11-05)
MODEL_PRICING = {
    "claude-sonnet-4.5-20250929": {
        "input": 3.00,  # per million tokens
        "output": 15.00,
        "cache_write": 3.75,
        "cache_read": 0.30,
    },
    "claude-3-5-sonnet-20241022": {
        "input": 3.00,
        "output": 15.00,
        "cache_write": 3.75,
        "cache_read": 0.30,
    },
    "claude-3-opus-20240229": {
        "input": 15.00,
        "output": 75.00,
        "cache_write": 18.75,
        "cache_read": 1.50,
    },
    "claude-3-haiku-20240307": {
        "input": 0.25,
        "output": 1.25,
        "cache_write": 0.30,
        "cache_read": 0.03,
    },
}


class CostTracker:
    """
    Track API costs and token usage across sessions.

    Example:
        ```python
        tracker = CostTracker()

        # Track usage
        usage = UsageMetrics(input_tokens=1000, output_tokens=500)
        tracker.track_usage("session-1", usage, model="claude-sonnet-4.5-20250929")

        # Get report
        report = tracker.get_report("session-1")
        print(f"Total cost: ${report.total_cost_usd:.4f}")

        # Save report
        tracker.save_report("session-1", "cost_report.json")
        ```
    """

    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize cost tracker.

        Args:
            storage_path: Path to store cost tracking data
        """
        self.storage_path = Path(storage_path or ".reveng/cost_tracking")
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.sessions: Dict[str, CostReport] = {}
        self._load_sessions()

    def track_usage(
        self,
        session_id: str,
        usage: UsageMetrics,
        model: str = "claude-sonnet-4.5-20250929",
        tool_name: Optional[str] = None,
    ):
        """
        Track usage for a session.

        Args:
            session_id: Unique session identifier
            usage: Usage metrics to track
            model: Model name for pricing
            tool_name: Name of tool used (optional)
        """
        # Get or create session report
        if session_id not in self.sessions:
            self.sessions[session_id] = CostReport(
                session_id=session_id, model=model, start_time=datetime.now().isoformat()
            )

        report = self.sessions[session_id]

        # Get pricing for model
        pricing = MODEL_PRICING.get(model, MODEL_PRICING["claude-sonnet-4.5-20250929"])

        # Add usage to report
        report.add_usage(usage, pricing)

        # Track tool usage
        if tool_name:
            report.tool_calls += 1
            if "tools_used" not in report.metadata:
                report.metadata["tools_used"] = {}
            report.metadata["tools_used"][tool_name] = (
                report.metadata["tools_used"].get(tool_name, 0) + 1
            )

        # Update timestamp
        report.end_time = datetime.now().isoformat()

        # Save to disk
        self._save_session(session_id)

    def get_report(self, session_id: str) -> Optional[CostReport]:
        """Get cost report for a session"""
        return self.sessions.get(session_id)

    def get_all_reports(self) -> List[CostReport]:
        """Get all cost reports"""
        return list(self.sessions.values())

    def get_total_cost(self) -> float:
        """Get total cost across all sessions"""
        return sum(report.total_cost_usd for report in self.sessions.values())

    def get_total_tokens(self) -> int:
        """Get total tokens across all sessions"""
        return sum(report.total_tokens for report in self.sessions.values())

    def save_report(self, session_id: str, output_path: str):
        """
        Save cost report to file.

        Args:
            session_id: Session to save
            output_path: Path to save JSON report
        """
        report = self.sessions.get(session_id)
        if not report:
            raise ValueError(f"Session not found: {session_id}")

        with open(output_path, "w") as f:
            json.dump(asdict(report), f, indent=2)

    def export_csv(self, output_path: str):
        """
        Export all reports to CSV.

        Args:
            output_path: Path to save CSV file
        """
        import csv

        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)

            # Header
            writer.writerow(
                [
                    "Session ID",
                    "Model",
                    "Total Cost (USD)",
                    "Total Tokens",
                    "Input Tokens",
                    "Output Tokens",
                    "Cache Tokens",
                    "Steps",
                    "Tool Calls",
                    "Start Time",
                    "End Time",
                ]
            )

            # Data
            for report in self.sessions.values():
                writer.writerow(
                    [
                        report.session_id,
                        report.model,
                        f"{report.total_cost_usd:.4f}",
                        report.total_tokens,
                        report.input_tokens,
                        report.output_tokens,
                        report.cache_tokens,
                        report.steps,
                        report.tool_calls,
                        report.start_time,
                        report.end_time,
                    ]
                )

    def clear_session(self, session_id: str):
        """Clear a session's cost tracking data"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            session_file = self.storage_path / f"{session_id}.json"
            if session_file.exists():
                session_file.unlink()

    def clear_all(self):
        """Clear all cost tracking data"""
        self.sessions.clear()
        for session_file in self.storage_path.glob("*.json"):
            session_file.unlink()

    def _save_session(self, session_id: str):
        """Save session to disk"""
        report = self.sessions.get(session_id)
        if not report:
            return

        session_file = self.storage_path / f"{session_id}.json"
        with open(session_file, "w") as f:
            json.dump(asdict(report), f, indent=2)

    def _load_sessions(self):
        """Load sessions from disk"""
        if not self.storage_path.exists():
            return

        for session_file in self.storage_path.glob("*.json"):
            try:
                with open(session_file, "r") as f:
                    data = json.load(f)
                    report = CostReport(**data)
                    self.sessions[report.session_id] = report
            except Exception:
                pass  # Skip corrupted files


# Global cost tracker
_global_tracker = None


def get_global_tracker() -> CostTracker:
    """Get the global cost tracker instance"""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = CostTracker()
    return _global_tracker
