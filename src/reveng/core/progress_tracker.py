"""
Progress tracking for REVENG analysis operations
"""

import time
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class AnalysisStatus(Enum):
    """Analysis status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class AnalysisStage:
    """Analysis stage information"""
    name: str
    status: AnalysisStatus
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    progress: float = 0.0
    message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class ToolExecution:
    """Tool execution information"""
    tool_name: str
    command: List[str]
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    success: Optional[bool] = None
    output: Optional[str] = None
    error: Optional[str] = None

class ProgressTracker:
    """Track progress of analysis operations"""

    def __init__(self):
        self.analyses: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def start_analysis(self, binary_path: str, analysis_type: str) -> str:
        """Start tracking analysis"""
        analysis_id = f"{binary_path}_{int(time.time())}"

        with self._lock:
            self.analyses[analysis_id] = {
                'binary_path': binary_path,
                'analysis_type': analysis_type,
                'status': AnalysisStatus.RUNNING,
                'start_time': time.time(),
                'end_time': None,
                'duration': None,
                'stages': [],
                'tools_used': [],
                'errors': [],
                'progress': 0.0,
                'current_stage': None
            }

        return analysis_id

    def end_analysis(self, analysis_id: str, success: bool = True,
                    error_message: Optional[str] = None) -> float:
        """End analysis tracking"""
        with self._lock:
            if analysis_id in self.analyses:
                end_time = time.time()
                start_time = self.analyses[analysis_id]['start_time']
                duration = end_time - start_time

                self.analyses[analysis_id].update({
                    'status': AnalysisStatus.COMPLETED if success else AnalysisStatus.FAILED,
                    'end_time': end_time,
                    'duration': duration,
                    'progress': 100.0 if success else self.analyses[analysis_id]['progress']
                })

                if error_message:
                    self.analyses[analysis_id]['errors'].append({
                        'message': error_message,
                        'timestamp': end_time
                    })

                return duration
            return 0.0

    def start_stage(self, analysis_id: str, stage_name: str,
                   total_steps: Optional[int] = None) -> None:
        """Start analysis stage"""
        with self._lock:
            if analysis_id in self.analyses:
                stage = AnalysisStage(
                    name=stage_name,
                    status=AnalysisStatus.RUNNING,
                    start_time=time.time(),
                    metadata={'total_steps': total_steps}
                )

                self.analyses[analysis_id]['stages'].append(stage)
                self.analyses[analysis_id]['current_stage'] = stage_name

    def end_stage(self, analysis_id: str, stage_name: str,
                 success: bool = True, message: Optional[str] = None) -> None:
        """End analysis stage"""
        with self._lock:
            if analysis_id in self.analyses:
                for stage in self.analyses[analysis_id]['stages']:
                    if stage.name == stage_name and stage.status == AnalysisStatus.RUNNING:
                        end_time = time.time()
                        stage.end_time = end_time
                        stage.duration = end_time - stage.start_time
                        stage.status = AnalysisStatus.COMPLETED if success else AnalysisStatus.FAILED
                        stage.message = message
                        break

    def update_stage_progress(self, analysis_id: str, stage_name: str,
                            progress: float, message: Optional[str] = None) -> None:
        """Update stage progress"""
        with self._lock:
            if analysis_id in self.analyses:
                for stage in self.analyses[analysis_id]['stages']:
                    if stage.name == stage_name:
                        stage.progress = min(100.0, max(0.0, progress))
                        if message:
                            stage.message = message
                        break

    def log_tool_execution(self, analysis_id: str, tool_name: str,
                          command: List[str]) -> None:
        """Log tool execution start"""
        with self._lock:
            if analysis_id in self.analyses:
                execution = ToolExecution(
                    tool_name=tool_name,
                    command=command,
                    start_time=time.time()
                )

                self.analyses[analysis_id]['tools_used'].append(execution)

    def log_tool_result(self, analysis_id: str, tool_name: str,
                       success: bool, output: Optional[str] = None,
                       error: Optional[str] = None) -> None:
        """Log tool execution result"""
        with self._lock:
            if analysis_id in self.analyses:
                # Find the most recent tool execution
                for execution in reversed(self.analyses[analysis_id]['tools_used']):
                    if execution.tool_name == tool_name and execution.end_time is None:
                        end_time = time.time()
                        execution.end_time = end_time
                        execution.duration = end_time - execution.start_time
                        execution.success = success
                        execution.output = output
                        execution.error = error
                        break

    def log_error(self, analysis_id: str, error_message: str,
                 error_type: str = "unknown") -> None:
        """Log error"""
        with self._lock:
            if analysis_id in self.analyses:
                self.analyses[analysis_id]['errors'].append({
                    'message': error_message,
                    'type': error_type,
                    'timestamp': time.time()
                })

    def get_analysis_status(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Get analysis status"""
        with self._lock:
            return self.analyses.get(analysis_id)

    def get_all_analyses(self) -> List[Dict[str, Any]]:
        """Get all analyses"""
        with self._lock:
            return list(self.analyses.values())

    def get_running_analyses(self) -> List[Dict[str, Any]]:
        """Get running analyses"""
        with self._lock:
            return [
                analysis for analysis in self.analyses.values()
                if analysis['status'] == AnalysisStatus.RUNNING
            ]

    def get_analysis_summary(self, analysis_id: str) -> Dict[str, Any]:
        """Get analysis summary"""
        with self._lock:
            if analysis_id not in self.analyses:
                return {}

            analysis = self.analyses[analysis_id]

            # Calculate overall progress
            total_stages = len(analysis['stages'])
            if total_stages > 0:
                completed_stages = sum(
                    1 for stage in analysis['stages']
                    if stage.status == AnalysisStatus.COMPLETED
                )
                analysis['progress'] = (completed_stages / total_stages) * 100

            # Count tools and errors
            tools_count = len(analysis['tools_used'])
            successful_tools = sum(
                1 for tool in analysis['tools_used']
                if tool.success is True
            )
            errors_count = len(analysis['errors'])

            return {
                'analysis_id': analysis_id,
                'binary_path': analysis['binary_path'],
                'analysis_type': analysis['analysis_type'],
                'status': analysis['status'].value,
                'progress': analysis['progress'],
                'duration': analysis['duration'],
                'stages_count': total_stages,
                'tools_count': tools_count,
                'successful_tools': successful_tools,
                'errors_count': errors_count,
                'current_stage': analysis.get('current_stage'),
                'start_time': analysis['start_time'],
                'end_time': analysis.get('end_time')
            }

    def cancel_analysis(self, analysis_id: str) -> bool:
        """Cancel analysis"""
        with self._lock:
            if analysis_id in self.analyses:
                self.analyses[analysis_id]['status'] = AnalysisStatus.CANCELLED
                self.analyses[analysis_id]['end_time'] = time.time()
                return True
            return False

    def clear_completed(self) -> int:
        """Clear completed analyses"""
        with self._lock:
            initial_count = len(self.analyses)
            self.analyses = {
                aid: analysis for aid, analysis in self.analyses.items()
                if analysis['status'] == AnalysisStatus.RUNNING
            }
            return initial_count - len(self.analyses)

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        with self._lock:
            total_analyses = len(self.analyses)
            completed = sum(
                1 for analysis in self.analyses.values()
                if analysis['status'] == AnalysisStatus.COMPLETED
            )
            failed = sum(
                1 for analysis in self.analyses.values()
                if analysis['status'] == AnalysisStatus.FAILED
            )
            running = sum(
                1 for analysis in self.analyses.values()
                if analysis['status'] == AnalysisStatus.RUNNING
            )

            total_duration = sum(
                analysis.get('duration', 0) for analysis in self.analyses.values()
                if analysis.get('duration')
            )

            return {
                'total_analyses': total_analyses,
                'completed': completed,
                'failed': failed,
                'running': running,
                'success_rate': (completed / total_analyses * 100) if total_analyses > 0 else 0,
                'total_duration': total_duration,
                'average_duration': total_duration / completed if completed > 0 else 0
            }
