"""
REVENG Enhanced Logging System

Structured logging with context, progress tracking, and log aggregation.
"""

import logging
import sys
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from contextlib import contextmanager

class LogLevel(Enum):
    """Log levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass
class LogContext:
    """Context information for logging"""
    component: str
    operation: str
    binary_path: Optional[str] = None
    tool_name: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    additional_info: Optional[Dict[str, Any]] = None

@dataclass
class ProgressInfo:
    """Progress information"""
    current_step: int
    total_steps: int
    step_name: str
    percentage: float
    start_time: float
    estimated_completion: Optional[float] = None

class StructuredFormatter(logging.Formatter):
    """Structured log formatter"""

    def __init__(self, include_context: bool = True, include_stack_trace: bool = False):
        super().__init__()
        self.include_context = include_context
        self.include_stack_trace = include_stack_trace

    def format(self, record):
        """Format log record with structured information"""
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }

        # Add context if available
        if hasattr(record, 'context') and self.include_context:
            log_entry['context'] = asdict(record.context)

        # Add stack trace if requested
        if self.include_stack_trace and record.exc_info:
            log_entry['stack_trace'] = self.formatException(record.exc_info)

        # Add progress info if available
        if hasattr(record, 'progress'):
            log_entry['progress'] = asdict(record.progress)

        return json.dumps(log_entry, indent=2)

class ProgressTracker:
    """Progress tracking for long operations"""

    def __init__(self, total_steps: int, operation_name: str):
        self.total_steps = total_steps
        self.current_step = 0
        self.operation_name = operation_name
        self.start_time = time.time()
        self.step_times = []
        self.logger = logging.getLogger("progress")

    def update(self, step_name: str, step_number: Optional[int] = None):
        """Update progress"""
        if step_number is not None:
            self.current_step = step_number
        else:
            self.current_step += 1

        current_time = time.time()
        self.step_times.append(current_time)

        percentage = (self.current_step / self.total_steps) * 100

        # Calculate estimated completion time
        if self.current_step > 0:
            avg_time_per_step = (current_time - self.start_time) / self.current_step
            estimated_completion = self.start_time + (avg_time_per_step * self.total_steps)
        else:
            estimated_completion = None

        progress_info = ProgressInfo(
            current_step=self.current_step,
            total_steps=self.total_steps,
            step_name=step_name,
            percentage=percentage,
            start_time=self.start_time,
            estimated_completion=estimated_completion
        )

        # Log progress
        self.logger.info(
            f"Progress: {step_name} ({self.current_step}/{self.total_steps}) - {percentage:.1f}%",
            extra={'progress': progress_info}
        )

    def complete(self):
        """Mark operation as complete"""
        total_time = time.time() - self.start_time
        self.logger.info(
            f"Operation '{self.operation_name}' completed in {total_time:.2f} seconds"
        )

class LogAggregator:
    """Log aggregation for analysis pipelines"""

    def __init__(self):
        self.logs = []
        self.lock = threading.Lock()

    def add_log(self, level: str, message: str, context: Optional[LogContext] = None):
        """Add log entry"""
        with self.lock:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'level': level,
                'message': message,
                'context': asdict(context) if context else None
            }
            self.logs.append(log_entry)

    def get_logs(self, level_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get filtered logs"""
        with self.lock:
            if level_filter:
                return [log for log in self.logs if log['level'] == level_filter]
            return self.logs.copy()

    def export_logs(self, file_path: str, format: str = 'json'):
        """Export logs to file"""
        with self.lock:
            if format == 'json':
                with open(file_path, 'w') as f:
                    json.dump(self.logs, f, indent=2)
            elif format == 'txt':
                with open(file_path, 'w') as f:
                    for log in self.logs:
                        f.write(f"[{log['timestamp']}] {log['level']}: {log['message']}\n")

    def clear_logs(self):
        """Clear all logs"""
        with self.lock:
            self.logs.clear()

class REVENGLogger:
    """Enhanced REVENG logger with context and progress tracking"""

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.context: Optional[LogContext] = None
        self.progress_tracker: Optional[ProgressTracker] = None
        self.aggregator = LogAggregator()

    def set_context(self, context: LogContext):
        """Set logging context"""
        self.context = context

    def start_progress(self, total_steps: int, operation_name: str):
        """Start progress tracking"""
        self.progress_tracker = ProgressTracker(total_steps, operation_name)

    def update_progress(self, step_name: str, step_number: Optional[int] = None):
        """Update progress"""
        if self.progress_tracker:
            self.progress_tracker.update(step_name, step_number)

    def complete_progress(self):
        """Complete progress tracking"""
        if self.progress_tracker:
            self.progress_tracker.complete()
            self.progress_tracker = None

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message"""
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message"""
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self._log(logging.CRITICAL, message, **kwargs)

    def _log(self, level: int, message: str, **kwargs):
        """Internal logging method"""
        extra = kwargs.get('extra', {})

        # Add context to extra
        if self.context:
            extra['context'] = self.context

        # Add progress to extra
        if self.progress_tracker:
            extra['progress'] = self.progress_tracker

        # Log to standard logger
        self.logger.log(level, message, extra=extra)

        # Add to aggregator
        self.aggregator.add_log(
            logging.getLevelName(level),
            message,
            self.context
        )

    def get_aggregated_logs(self, level_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get aggregated logs"""
        return self.aggregator.get_logs(level_filter)

    def export_logs(self, file_path: str, format: str = 'json'):
        """Export logs"""
        self.aggregator.export_logs(file_path, format)

def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    structured: bool = True,
    include_stack_trace: bool = False
) -> logging.Logger:
    """Setup REVENG logging system"""

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))

    if structured:
        console_formatter = StructuredFormatter(
            include_context=True,
            include_stack_trace=include_stack_trace
        )
    else:
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)

        if structured:
            file_formatter = StructuredFormatter(
                include_context=True,
                include_stack_trace=True
            )
        else:
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )

        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    return root_logger

def get_logger(name: str) -> REVENGLogger:
    """Get REVENG logger instance"""
    return REVENGLogger(name)

@contextmanager
def log_context(component: str, operation: str, **kwargs):
    """Context manager for logging with automatic context"""
    logger = get_logger(f"{component}.{operation}")
    context = LogContext(
        component=component,
        operation=operation,
        **kwargs
    )
    logger.set_context(context)

    try:
        yield logger
    finally:
        logger.complete_progress()

@contextmanager
def progress_tracking(logger: REVENGLogger, total_steps: int, operation_name: str):
    """Context manager for progress tracking"""
    logger.start_progress(total_steps, operation_name)

    try:
        yield logger
    finally:
        logger.complete_progress()

def log_analysis_start(logger: REVENGLogger, binary_path: str, analysis_type: str):
    """Log analysis start"""
    logger.info(f"Starting {analysis_type} analysis of {binary_path}")
    logger.set_context(LogContext(
        component="analyzer",
        operation=analysis_type,
        binary_path=binary_path
    ))

def log_analysis_complete(logger: REVENGLogger, binary_path: str, analysis_type: str, duration: float):
    """Log analysis completion"""
    logger.info(f"Completed {analysis_type} analysis of {binary_path} in {duration:.2f} seconds")

def log_tool_execution(logger: REVENGLogger, tool_name: str, command: str, success: bool):
    """Log tool execution"""
    if success:
        logger.info(f"Tool {tool_name} executed successfully: {command}")
    else:
        logger.error(f"Tool {tool_name} execution failed: {command}")

def log_error_with_context(logger: REVENGLogger, error: Exception, context: Optional[LogContext] = None):
    """Log error with context"""
    if context:
        logger.set_context(context)

    logger.error(f"Error: {str(error)}")
    if hasattr(error, 'get_detailed_message'):
        logger.error(f"Details: {error.get_detailed_message()}")

    if hasattr(error, 'recovery_suggestions') and error.recovery_suggestions:
        logger.info("Recovery suggestions:")
        for suggestion in error.recovery_suggestions:
            logger.info(f"  - {suggestion.description}")
            if suggestion.command:
                logger.info(f"    Command: {suggestion.command}")

# Global log aggregator for analysis pipelines
global_aggregator = LogAggregator()

def get_global_aggregator() -> LogAggregator:
    """Get global log aggregator"""
    return global_aggregator
