"""
Gemini Continuous Feedback Loop

This module runs Gemini in the background to continuously analyze the codebase
and suggest improvements, find bugs, and optimize the reverse engineering pipeline.

This is the "meta" AI layer - AI analyzing and improving our AI reverse engineering tool.

Author: REVENG Team
Version: 3.0.0
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from reveng.ai.gemini_engine import GeminiEngine

logger = logging.getLogger(__name__)


class GeminiFeedbackLoop:
    """
    Continuous improvement system using Gemini.

    This runs in the background and:
    1. Analyzes reconstruction results
    2. Suggests code improvements
    3. Finds bugs in our analysis pipeline
    4. Recommends new features
    5. Optimizes performance
    """

    def __init__(
        self,
        project_root: Path,
        output_dir: Path,
        interval_minutes: int = 5,
        auto_apply: bool = False,
    ):
        """
        Initialize feedback loop.

        Args:
            project_root: Root directory of REVENG project
            output_dir: Directory to save feedback reports
            interval_minutes: How often to run analysis
            auto_apply: Automatically apply safe improvements (EXPERIMENTAL)
        """
        self.project_root = Path(project_root)
        self.output_dir = Path(output_dir)
        self.interval_minutes = interval_minutes
        self.auto_apply = auto_apply

        self.gemini = GeminiEngine()
        self.feedback_history = []

        logger.info(f"Gemini Feedback Loop initialized (interval: {interval_minutes}m)")

    async def start(self, max_iterations: Optional[int] = None):
        """
        Start the continuous feedback loop.

        Args:
            max_iterations: Maximum iterations (None = infinite)
        """
        logger.info("🔄 Starting Gemini Feedback Loop...")

        if not self.gemini.is_available():
            logger.error("❌ Gemini not available. Set GEMINI_API_KEY environment variable.")
            return

        iteration = 0
        while max_iterations is None or iteration < max_iterations:
            iteration += 1

            logger.info(f"\n{'='*60}")
            logger.info(f"Feedback Loop Iteration #{iteration}")
            logger.info(f"{'='*60}")

            try:
                # Phase 1: Analyze current state
                state = await self._analyze_current_state()

                # Phase 2: Get Gemini feedback
                feedback = await self._get_gemini_feedback(state)

                # Phase 3: Process feedback
                await self._process_feedback(feedback)

                # Phase 4: Generate report
                await self._generate_feedback_report(iteration, state, feedback)

                # Wait before next iteration
                logger.info(f"\n⏰ Next iteration in {self.interval_minutes} minutes...")
                await asyncio.sleep(self.interval_minutes * 60)

            except KeyboardInterrupt:
                logger.info("\n⏸️ Feedback loop interrupted by user")
                break
            except Exception as e:
                logger.error(f"❌ Iteration failed: {e}", exc_info=True)
                await asyncio.sleep(60)  # Wait 1 minute on error

        logger.info(f"\n✅ Feedback loop completed after {iteration} iterations")

    async def _analyze_current_state(self) -> Dict[str, Any]:
        """Analyze the current state of the project."""
        logger.info("📊 Analyzing project state...")

        state = {
            "timestamp": datetime.now().isoformat(),
            "project_root": str(self.project_root),
            "codebase_stats": {},
            "recent_results": [],
            "errors": [],
            "performance": {},
        }

        # Count Python files
        py_files = list(self.project_root.rglob("src/**/*.py"))
        state["codebase_stats"]["python_files"] = len(py_files)
        state["codebase_stats"]["total_loc"] = sum(
            len(f.read_text().split("\n")) for f in py_files[:100]  # Sample first 100
        )

        # Check recent reconstruction results
        analysis_dirs = list(self.output_dir.glob("analysis_*"))
        state["recent_results"] = [
            str(d.name) for d in sorted(analysis_dirs, key=lambda x: x.stat().st_mtime)[-5:]
        ]

        # Check for errors in logs
        log_file = self.project_root / "reveng_analyzer.log"
        if log_file.exists():
            log_content = log_file.read_text()
            error_lines = [line for line in log_content.split("\n") if "ERROR" in line]
            state["errors"] = error_lines[-10:]  # Last 10 errors

        logger.info(f"  ✅ Python files: {state['codebase_stats']['python_files']}")
        logger.info(f"  ✅ Recent analyses: {len(state['recent_results'])}")
        logger.info(f"  ✅ Recent errors: {len(state['errors'])}")

        return state

    async def _get_gemini_feedback(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Get improvement suggestions from Gemini."""
        logger.info("🤖 Requesting Gemini analysis...")

        prompt = f"""You are a senior security researcher and software architect analyzing the REVENG reverse engineering platform.

Current State:
- Python Files: {state['codebase_stats'].get('python_files', 0)}
- Total LOC: ~{state['codebase_stats'].get('total_loc', 0):,}
- Recent Analyses: {len(state['recent_results'])}
- Recent Errors: {len(state['errors'])}

Recent Error Log:
```
{chr(10).join(state['errors'][:5])}
```

Provide actionable feedback in these areas:

1. **Architecture Improvements**: How can we improve the codebase structure?
2. **Bug Fixes**: What bugs do you see in the error log?
3. **Performance**: How can we make analysis faster?
4. **Security**: Are there security issues in our code?
5. **AI Enhancement**: How can we improve AI-powered reconstruction?
6. **New Features**: What revolutionary features should we add?

Format your response as JSON:
{{
  "architecture": ["suggestion 1", "suggestion 2"],
  "bugs": [
    {{
      "issue": "description",
      "location": "file:line",
      "fix": "how to fix"
    }}
  ],
  "performance": ["optimization 1", "optimization 2"],
  "security": ["security issue 1"],
  "ai_enhancements": ["enhancement 1"],
  "new_features": ["feature 1", "feature 2"],
  "priority_actions": [
    {{
      "action": "what to do",
      "priority": "critical|high|medium|low",
      "effort": "minutes|hours|days"
    }}
  ]
}}

Be specific and actionable. Focus on high-impact improvements.
"""

        try:
            response = await self.gemini._generate_async(prompt)

            # Parse JSON response
            import json

            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()

            feedback = json.loads(response)
            self.feedback_history.append(feedback)

            logger.info("  ✅ Gemini feedback received")
            return feedback

        except Exception as e:
            logger.error(f"  ❌ Failed to get Gemini feedback: {e}")
            return {}

    async def _process_feedback(self, feedback: Dict[str, Any]):
        """Process and optionally apply feedback."""
        logger.info("⚙️ Processing feedback...")

        # Count suggestions
        total_suggestions = (
            len(feedback.get("architecture", []))
            + len(feedback.get("bugs", []))
            + len(feedback.get("performance", []))
            + len(feedback.get("security", []))
            + len(feedback.get("ai_enhancements", []))
            + len(feedback.get("new_features", []))
        )

        logger.info(f"  📝 Total suggestions: {total_suggestions}")

        # Show priority actions
        priority_actions = feedback.get("priority_actions", [])
        if priority_actions:
            logger.info("\n  🎯 Priority Actions:")
            for action in priority_actions[:5]:
                priority = action.get("priority", "unknown")
                effort = action.get("effort", "unknown")
                desc = action.get("action", "")
                icon = "🔴" if priority == "critical" else "🟡" if priority == "high" else "🟢"
                logger.info(f"    {icon} [{priority.upper()}] {desc} (effort: {effort})")

        # Auto-apply safe improvements (if enabled)
        if self.auto_apply:
            logger.info("\n  🤖 Auto-applying safe improvements...")
            applied = await self._auto_apply_improvements(feedback)
            logger.info(f"  ✅ Applied {applied} improvements")

    async def _auto_apply_improvements(self, feedback: Dict[str, Any]) -> int:
        """
        Automatically apply safe improvements.

        This is EXPERIMENTAL and only applies very safe changes like:
        - Adding missing docstrings
        - Fixing typos in comments
        - Adding type hints
        - Updating documentation

        Args:
            feedback: Gemini feedback

        Returns:
            int: Number of improvements applied
        """
        applied = 0

        # Currently disabled for safety
        logger.warning("  ⚠️ Auto-apply is experimental and currently disabled")

        # In the future, we could:
        # 1. Parse feedback for "safe" improvements
        # 2. Generate code patches
        # 3. Apply patches with git
        # 4. Run tests
        # 5. Commit if tests pass

        return applied

    async def _generate_feedback_report(
        self, iteration: int, state: Dict[str, Any], feedback: Dict[str, Any]
    ):
        """Generate a markdown report of the feedback."""
        report_path = self.output_dir / f"feedback_iteration_{iteration:03d}.md"

        report = []
        report.append(f"# Gemini Feedback Report - Iteration #{iteration}")
        report.append("")
        report.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        report.append("## Project State")
        report.append("")
        report.append(f"- Python Files: {state['codebase_stats'].get('python_files', 0)}")
        report.append(f"- Total LOC: ~{state['codebase_stats'].get('total_loc', 0):,}")
        report.append(f"- Recent Analyses: {len(state['recent_results'])}")
        report.append(f"- Recent Errors: {len(state['errors'])}")
        report.append("")

        if feedback:
            if feedback.get("architecture"):
                report.append("## Architecture Improvements")
                report.append("")
                for suggestion in feedback["architecture"]:
                    report.append(f"- {suggestion}")
                report.append("")

            if feedback.get("bugs"):
                report.append("## Bug Fixes")
                report.append("")
                for bug in feedback["bugs"]:
                    report.append(f"### {bug.get('issue')}")
                    report.append(f"- **Location**: {bug.get('location')}")
                    report.append(f"- **Fix**: {bug.get('fix')}")
                    report.append("")

            if feedback.get("performance"):
                report.append("## Performance Optimizations")
                report.append("")
                for opt in feedback["performance"]:
                    report.append(f"- {opt}")
                report.append("")

            if feedback.get("security"):
                report.append("## Security Issues")
                report.append("")
                for issue in feedback["security"]:
                    report.append(f"- {issue}")
                report.append("")

            if feedback.get("ai_enhancements"):
                report.append("## AI Enhancements")
                report.append("")
                for enhancement in feedback["ai_enhancements"]:
                    report.append(f"- {enhancement}")
                report.append("")

            if feedback.get("new_features"):
                report.append("## Proposed New Features")
                report.append("")
                for feature in feedback["new_features"]:
                    report.append(f"- {feature}")
                report.append("")

            if feedback.get("priority_actions"):
                report.append("## Priority Actions")
                report.append("")
                report.append("| Priority | Action | Effort |")
                report.append("|----------|--------|--------|")
                for action in feedback["priority_actions"]:
                    priority = action.get("priority", "unknown")
                    desc = action.get("action", "")
                    effort = action.get("effort", "unknown")
                    report.append(f"| {priority.upper()} | {desc} | {effort} |")
                report.append("")

        report_path.write_text("\n".join(report), encoding="utf-8")
        logger.info(f"  📄 Report saved to: {report_path}")


# CLI helper
async def run_feedback_loop(
    project_root: str = ".",
    output_dir: str = "gemini_feedback",
    interval_minutes: int = 5,
    max_iterations: Optional[int] = None,
):
    """Run the Gemini feedback loop from CLI."""
    loop = GeminiFeedbackLoop(
        project_root=Path(project_root),
        output_dir=Path(output_dir),
        interval_minutes=interval_minutes,
    )

    await loop.start(max_iterations=max_iterations)


# Synchronous wrapper
def run_feedback_loop_sync(**kwargs):
    """Synchronous wrapper for the feedback loop."""
    return asyncio.run(run_feedback_loop(**kwargs))
