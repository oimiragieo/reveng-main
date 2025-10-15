#!/usr/bin/env python3
"""
REVENG Progress Reporter
=========================

Provides progress reporting for long-running operations using tqdm.

Features:
- Step-based progress tracking
- File processing progress bars
- Nested progress for multi-stage operations
- Automatic time estimation
- Memory-efficient for large datasets
"""

import logging
from typing import Optional, Iterator, Callable, Any
from pathlib import Path

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    logging.warning("tqdm not installed - progress bars disabled")

logger = logging.getLogger(__name__)


class ProgressReporter:
    """Progress reporting with tqdm"""

    def __init__(self, enabled: bool = True):
        """
        Initialize progress reporter

        Args:
            enabled: Whether to show progress bars (default: True)
        """
        self.enabled = enabled and HAS_TQDM
        self.current_bars = []

    def step(
        self,
        iterable: Iterator,
        desc: str,
        total: Optional[int] = None,
        unit: str = "item"
    ) -> Iterator:
        """
        Wrap an iterable with a progress bar

        Args:
            iterable: Iterable to wrap
            desc: Description of the operation
            total: Total number of items (auto-detected if possible)
            unit: Unit name for items

        Returns:
            Iterator with progress reporting

        Example:
            for item in progress.step(items, "Processing files", unit="file"):
                process(item)
        """
        if not self.enabled:
            return iterable

        return tqdm(
            iterable,
            desc=desc,
            total=total,
            unit=unit,
            leave=False,
            ncols=100
        )

    def track(
        self,
        total: int,
        desc: str,
        unit: str = "item"
    ) -> 'ProgressBar':
        """
        Create a manual progress bar

        Args:
            total: Total number of items
            desc: Description of the operation
            unit: Unit name for items

        Returns:
            ProgressBar object with update() method

        Example:
            with progress.track(100, "Processing") as pbar:
                for i in range(100):
                    process(i)
                    pbar.update(1)
        """
        if not self.enabled:
            return NoOpProgressBar()

        return ProgressBar(total, desc, unit)

    def pipeline_progress(self, total_steps: int = 8) -> 'PipelineProgress':
        """
        Create pipeline progress tracker

        Args:
            total_steps: Number of pipeline steps

        Returns:
            PipelineProgress object

        Example:
            pipeline = progress.pipeline_progress(8)
            pipeline.start_step(1, "AI Analysis")
            # ... do work ...
            pipeline.complete_step()
        """
        if not self.enabled:
            return NoOpPipelineProgress()

        return PipelineProgress(total_steps)


class ProgressBar:
    """Manual progress bar wrapper"""

    def __init__(self, total: int, desc: str, unit: str):
        """Initialize progress bar"""
        self.pbar = tqdm(
            total=total,
            desc=desc,
            unit=unit,
            leave=False,
            ncols=100
        )

    def update(self, n: int = 1):
        """Update progress by n items"""
        self.pbar.update(n)

    def set_description(self, desc: str):
        """Update description"""
        self.pbar.set_description(desc)

    def close(self):
        """Close progress bar"""
        self.pbar.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class PipelineProgress:
    """Pipeline-specific progress tracking"""

    def __init__(self, total_steps: int):
        """Initialize pipeline progress"""
        self.total_steps = total_steps
        self.current_step = 0
        self.main_bar = tqdm(
            total=total_steps,
            desc="REVENG Pipeline",
            unit="step",
            ncols=100,
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'
        )
        self.step_bar = None

    def start_step(
        self,
        step_num: int,
        step_name: str,
        substeps: Optional[int] = None
    ):
        """
        Start a pipeline step

        Args:
            step_num: Step number (1-based)
            step_name: Name of the step
            substeps: Number of substeps (for nested progress)
        """
        self.current_step = step_num

        # Update main progress bar
        self.main_bar.set_description(f"Step {step_num}/{self.total_steps}: {step_name}")

        # Create substep bar if needed
        if substeps:
            self.step_bar = tqdm(
                total=substeps,
                desc=f"  {step_name}",
                unit="op",
                leave=False,
                ncols=100
            )

    def update_substep(self, n: int = 1, desc: Optional[str] = None):
        """
        Update substep progress

        Args:
            n: Number of substeps completed
            desc: Optional description update
        """
        if self.step_bar:
            self.step_bar.update(n)
            if desc:
                self.step_bar.set_description(f"  {desc}")

    def complete_step(self):
        """Mark current step as complete"""
        if self.step_bar:
            self.step_bar.close()
            self.step_bar = None

        self.main_bar.update(1)

    def close(self):
        """Close all progress bars"""
        if self.step_bar:
            self.step_bar.close()
        self.main_bar.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class NoOpProgressBar:
    """No-op progress bar for when tqdm is disabled"""

    def update(self, n: int = 1):
        pass

    def set_description(self, desc: str):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class NoOpPipelineProgress:
    """No-op pipeline progress for when tqdm is disabled"""

    def start_step(self, step_num: int, step_name: str, substeps: Optional[int] = None):
        pass

    def update_substep(self, n: int = 1, desc: Optional[str] = None):
        pass

    def complete_step(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# Global instance
_global_reporter = ProgressReporter()


def get_progress_reporter(enabled: Optional[bool] = None) -> ProgressReporter:
    """
    Get global progress reporter instance

    Args:
        enabled: Override enabled state (None = use default)

    Returns:
        ProgressReporter instance
    """
    global _global_reporter

    if enabled is not None:
        _global_reporter.enabled = enabled and HAS_TQDM

    return _global_reporter


# Convenience functions
def track_progress(iterable: Iterator, desc: str, **kwargs) -> Iterator:
    """
    Convenience function for tracking progress

    Example:
        for item in track_progress(items, "Processing"):
            process(item)
    """
    return _global_reporter.step(iterable, desc, **kwargs)


def create_progress_bar(total: int, desc: str, **kwargs) -> ProgressBar:
    """
    Convenience function for creating manual progress bar

    Example:
        with create_progress_bar(100, "Processing") as pbar:
            for i in range(100):
                process(i)
                pbar.update()
    """
    return _global_reporter.track(total, desc, **kwargs)


# Example usage
if __name__ == "__main__":
    import time

    print("=" * 70)
    print("REVENG PROGRESS REPORTER DEMO")
    print("=" * 70)
    print()

    if not HAS_TQDM:
        print("ERROR: tqdm not installed")
        print("Install with: pip install tqdm")
        exit(1)

    progress = ProgressReporter()

    # Demo 1: Simple iteration progress
    print("Demo 1: File processing progress")
    files = [f"file_{i}.c" for i in range(50)]

    for filename in progress.step(files, "Processing C files", unit="file"):
        time.sleep(0.05)  # Simulate processing

    print("✓ File processing complete\n")

    # Demo 2: Manual progress bar
    print("Demo 2: Manual progress updates")
    with progress.track(100, "Analyzing functions", unit="func") as pbar:
        for i in range(100):
            time.sleep(0.02)  # Simulate work
            pbar.update(1)

    print("✓ Analysis complete\n")

    # Demo 3: Pipeline progress
    print("Demo 3: Pipeline with substeps")
    with progress.pipeline_progress(8) as pipeline:
        # Step 1
        pipeline.start_step(1, "AI Analysis", substeps=10)
        for i in range(10):
            time.sleep(0.1)
            pipeline.update_substep(1, f"Analyzing chunk {i+1}")
        pipeline.complete_step()

        # Step 2
        pipeline.start_step(2, "Disassembly", substeps=50)
        for i in range(50):
            time.sleep(0.03)
            pipeline.update_substep(1)
        pipeline.complete_step()

        # Step 3-8 (simple steps)
        for step in range(3, 9):
            pipeline.start_step(step, f"Step {step}")
            time.sleep(0.5)
            pipeline.complete_step()

    print("✓ Pipeline complete\n")

    print("=" * 70)
    print("All demos completed successfully!")
    print("=" * 70)
