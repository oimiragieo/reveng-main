#!/usr/bin/env python3
"""
Enhanced Analysis Health Monitor
===============================

Health monitoring and service management for AI-Enhanced Universal Analysis Engine.
Provides real-time monitoring, alerting, and automatic recovery capabilities.

Author: REVENG Project - Health Monitoring Module
Version: 1.0
"""

import time
import json
import logging
import threading
import psutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import subprocess
import sys

logger = logging.getLogger(__name__)


@dataclass
class HealthMetric:
    """Individual health metric"""
    name: str
    value: Any
    status: str  # "healthy", "warning", "critical"
    timestamp: datetime
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    message: str = ""


@dataclass
class ComponentHealth:
    """Health status for a component"""
    component_name: str
    status: str  # "healthy", "warning", "critical", "unknown"
    metrics: List[HealthMetric]
    last_check: datetime
    uptime: float = 0.0
    error_count: int = 0
    recovery_attempts: int = 0


@dataclass
class SystemHealth:
    """Overall system health status"""
    overall_status: str
    components: Dict[str, ComponentHealth]
    system_metrics: List[HealthMetric]
    timestamp: datetime
    alerts: List[str]


class HealthChecker:
    """Base class for health checkers"""
    
    def __init__(self, component_name: str):
        self.component_name = component_name
        self.start_time = datetime.now()
    
    def check_health(self) -> ComponentHealth:
        """Check component health - to be implemented by subclasses"""
        raise NotImplementedError
    
    def get_uptime(self) -> float:
        """Get component uptime in seconds"""
        return (datetime.now() - self.start_time).total_seconds()


class CoreREVENGHealthChecker(HealthChecker):
    """Health checker for core REVENG components"""
    
    def __init__(self):
        super().__init__("core_reveng")
    
    def check_health(self) -> ComponentHealth:
        """Check core REVENG component health"""
        metrics = []
        error_count = 0
        
        # Check if core modules can be imported
        core_modules = [
            "reveng_analyzer",
            "tools.language_detector",
            "tools.config_manager",
            "tools.ollama_preflight"
        ]
        
        for module in core_modules:
            try:
                __import__(module)
                metrics.append(HealthMetric(
                    name=f"module_{module.split('.')[-1]}",
                    value="available",
                    status="healthy",
                    timestamp=datetime.now(),
                    message=f"Module {module} is available"
                ))
            except ImportError as e:
                error_count += 1
                metrics.append(HealthMetric(
                    name=f"module_{module.split('.')[-1]}",
                    value="unavailable",
                    status="critical",
                    timestamp=datetime.now(),
                    message=f"Module {module} import failed: {e}"
                ))
        
        # Check configuration files
        config_files = ["config/enhanced_analysis.json", "enhanced_analysis_config.json"]
        config_found = False
        
        for config_file in config_files:
            if Path(config_file).exists():
                config_found = True
                metrics.append(HealthMetric(
                    name="configuration",
                    value="available",
                    status="healthy",
                    timestamp=datetime.now(),
                    message=f"Configuration found: {config_file}"
                ))
                break
        
        if not config_found:
            metrics.append(HealthMetric(
                name="configuration",
                value="missing",
                status="warning",
                timestamp=datetime.now(),
                message="No configuration file found"
            ))
        
        # Determine overall status
        if error_count == 0:
            status = "healthy"
        elif error_count < len(core_modules) / 2:
            status = "warning"
        else:
            status = "critical"
        
        return ComponentHealth(
            component_name=self.component_name,
            status=status,
            metrics=metrics,
            last_check=datetime.now(),
            uptime=self.get_uptime(),
            error_count=error_count
        )


class EnhancedModulesHealthChecker(HealthChecker):
    """Health checker for enhanced analysis modules"""
    
    def __init__(self):
        super().__init__("enhanced_modules")
    
    def check_health(self) -> ComponentHealth:
        """Check enhanced modules health"""
        metrics = []
        error_count = 0
        
        # Check enhanced analysis modules
        enhanced_modules = [
            "tools.ai_enhanced_analyzer",
            "tools.corporate_exposure_detector",
            "tools.vulnerability_discovery_engine",
            "tools.threat_intelligence_correlator",
            "tools.demonstration_generator",
            "tools.enhanced_config_manager"
        ]
        
        for module in enhanced_modules:
            try:
                __import__(module)
                metrics.append(HealthMetric(
                    name=f"module_{module.split('.')[-1]}",
                    value="available",
                    status="healthy",
                    timestamp=datetime.now(),
                    message=f"Enhanced module {module} is available"
                ))
            except ImportError as e:
                error_count += 1
                metrics.append(HealthMetric(
                    name=f"module_{module.split('.')[-1]}",
                    value="unavailable",
                    status="critical",
                    timestamp=datetime.now(),
                    message=f"Enhanced module {module} import failed: {e}"
                ))
        
        # Check data models
        try:
            from tools.ai_enhanced_data_models import UniversalAnalysisResult
            metrics.append(HealthMetric(
                name="data_models",
                value="available",
                status="healthy",
                timestamp=datetime.now(),
                message="Enhanced data models are available"
            ))
        except ImportError as e:
            error_count += 1
            metrics.append(HealthMetric(
                name="data_models",
                value="unavailable",
                status="critical",
                timestamp=datetime.now(),
                message=f"Data models import failed: {e}"
            ))
        
        # Determine overall status
        if error_count == 0:
            status = "healthy"
        elif error_count < len(enhanced_modules) / 2:
            status = "warning"
        else:
            status = "critical"
        
        return ComponentHealth(
            component_name=self.component_name,
            status=status,
            metrics=metrics,
            last_check=datetime.now(),
            uptime=self.get_uptime(),
            error_count=error_count
        )


class AIServiceHealthChecker(HealthChecker):
    """Health checker for AI services"""
    
    def __init__(self):
        super().__init__("ai_service")
    
    def check_health(self) -> ComponentHealth:
        """Check AI service health"""
        metrics = []
        error_count = 0
        
        # Check Ollama availability
        try:
            from tools.ollama_preflight import OllamaPreflightChecker
            
            checker = OllamaPreflightChecker()
            success, results = checker.check_all()
            
            if success:
                metrics.append(HealthMetric(
                    name="ollama_service",
                    value="available",
                    status="healthy",
                    timestamp=datetime.now(),
                    message=f"Ollama available with {len(results.get('models_available', []))} models"
                ))
                
                # Check model availability
                models = results.get('models_available', [])
                if models:
                    metrics.append(HealthMetric(
                        name="ollama_models",
                        value=len(models),
                        status="healthy",
                        timestamp=datetime.now(),
                        message=f"Available models: {', '.join(models[:3])}{'...' if len(models) > 3 else ''}"
                    ))
                else:
                    metrics.append(HealthMetric(
                        name="ollama_models",
                        value=0,
                        status="warning",
                        timestamp=datetime.now(),
                        message="No Ollama models available"
                    ))
            else:
                error_count += 1
                metrics.append(HealthMetric(
                    name="ollama_service",
                    value="unavailable",
                    status="critical",
                    timestamp=datetime.now(),
                    message=f"Ollama unavailable: {results.get('errors', [])}"
                ))
        
        except ImportError as e:
            error_count += 1
            metrics.append(HealthMetric(
                name="ollama_service",
                value="unavailable",
                status="critical",
                timestamp=datetime.now(),
                message=f"Ollama preflight checker not available: {e}"
            ))
        
        # Check AI configuration
        try:
            from tools.enhanced_config_manager import get_enhanced_config
            
            config = get_enhanced_config()
            ai_config = config.ai_service
            
            metrics.append(HealthMetric(
                name="ai_configuration",
                value="valid",
                status="healthy",
                timestamp=datetime.now(),
                message=f"AI provider: {ai_config.provider}, model: {ai_config.model}"
            ))
            
        except Exception as e:
            error_count += 1
            metrics.append(HealthMetric(
                name="ai_configuration",
                value="invalid",
                status="warning",
                timestamp=datetime.now(),
                message=f"AI configuration issue: {e}"
            ))
        
        # Determine overall status
        if error_count == 0:
            status = "healthy"
        elif error_count == 1:
            status = "warning"
        else:
            status = "critical"
        
        return ComponentHealth(
            component_name=self.component_name,
            status=status,
            metrics=metrics,
            last_check=datetime.now(),
            uptime=self.get_uptime(),
            error_count=error_count
        )


class SystemResourcesHealthChecker(HealthChecker):
    """Health checker for system resources"""
    
    def __init__(self):
        super().__init__("system_resources")
    
    def check_health(self) -> ComponentHealth:
        """Check system resources health"""
        metrics = []
        error_count = 0
        
        # Check CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_status = "healthy"
        if cpu_percent > 90:
            cpu_status = "critical"
            error_count += 1
        elif cpu_percent > 70:
            cpu_status = "warning"
        
        metrics.append(HealthMetric(
            name="cpu_usage",
            value=cpu_percent,
            status=cpu_status,
            timestamp=datetime.now(),
            threshold_warning=70.0,
            threshold_critical=90.0,
            message=f"CPU usage: {cpu_percent:.1f}%"
        ))
        
        # Check memory usage
        memory = psutil.virtual_memory()
        memory_status = "healthy"
        if memory.percent > 90:
            memory_status = "critical"
            error_count += 1
        elif memory.percent > 80:
            memory_status = "warning"
        
        metrics.append(HealthMetric(
            name="memory_usage",
            value=memory.percent,
            status=memory_status,
            timestamp=datetime.now(),
            threshold_warning=80.0,
            threshold_critical=90.0,
            message=f"Memory usage: {memory.percent:.1f}% ({memory.used // (1024**3):.1f}GB / {memory.total // (1024**3):.1f}GB)"
        ))
        
        # Check disk usage
        disk = psutil.disk_usage('.')
        disk_percent = (disk.used / disk.total) * 100
        disk_status = "healthy"
        if disk_percent > 95:
            disk_status = "critical"
            error_count += 1
        elif disk_percent > 85:
            disk_status = "warning"
        
        metrics.append(HealthMetric(
            name="disk_usage",
            value=disk_percent,
            status=disk_status,
            timestamp=datetime.now(),
            threshold_warning=85.0,
            threshold_critical=95.0,
            message=f"Disk usage: {disk_percent:.1f}% ({disk.used // (1024**3):.1f}GB / {disk.total // (1024**3):.1f}GB)"
        ))
        
        # Check load average (Unix-like systems)
        try:
            load_avg = psutil.getloadavg()
            load_status = "healthy"
            cpu_count = psutil.cpu_count()
            
            if load_avg[0] > cpu_count * 2:
                load_status = "critical"
                error_count += 1
            elif load_avg[0] > cpu_count:
                load_status = "warning"
            
            metrics.append(HealthMetric(
                name="load_average",
                value=load_avg[0],
                status=load_status,
                timestamp=datetime.now(),
                threshold_warning=float(cpu_count),
                threshold_critical=float(cpu_count * 2),
                message=f"Load average: {load_avg[0]:.2f} (1min), {load_avg[1]:.2f} (5min), {load_avg[2]:.2f} (15min)"
            ))
        except AttributeError:
            # getloadavg not available on Windows
            pass
        
        # Determine overall status
        if error_count == 0:
            status = "healthy"
        elif error_count < 2:
            status = "warning"
        else:
            status = "critical"
        
        return ComponentHealth(
            component_name=self.component_name,
            status=status,
            metrics=metrics,
            last_check=datetime.now(),
            uptime=self.get_uptime(),
            error_count=error_count
        )


class EnhancedHealthMonitor:
    """
    Comprehensive health monitor for AI-Enhanced Universal Analysis Engine
    """
    
    def __init__(self, check_interval: int = 60):
        """
        Initialize health monitor
        
        Args:
            check_interval: Health check interval in seconds
        """
        self.check_interval = check_interval
        self.running = False
        self.monitor_thread = None
        
        # Health checkers
        self.checkers = {
            "core_reveng": CoreREVENGHealthChecker(),
            "enhanced_modules": EnhancedModulesHealthChecker(),
            "ai_service": AIServiceHealthChecker(),
            "system_resources": SystemResourcesHealthChecker()
        }
        
        # Health history
        self.health_history: List[SystemHealth] = []
        self.max_history_size = 1000
        
        # Alert callbacks
        self.alert_callbacks: List[Callable[[str, ComponentHealth], None]] = []
        
        logger.info("Enhanced Health Monitor initialized")
    
    def add_alert_callback(self, callback: Callable[[str, ComponentHealth], None]):
        """Add alert callback function"""
        self.alert_callbacks.append(callback)
    
    def check_all_components(self) -> SystemHealth:
        """Check health of all components"""
        components = {}
        alerts = []
        
        # Check each component
        for name, checker in self.checkers.items():
            try:
                component_health = checker.check_health()
                components[name] = component_health
                
                # Generate alerts for unhealthy components
                if component_health.status in ["warning", "critical"]:
                    alert_msg = f"Component {name} status: {component_health.status}"
                    alerts.append(alert_msg)
                    
                    # Call alert callbacks
                    for callback in self.alert_callbacks:
                        try:
                            callback(alert_msg, component_health)
                        except Exception as e:
                            logger.error(f"Alert callback failed: {e}")
                
            except Exception as e:
                logger.error(f"Health check failed for {name}: {e}")
                components[name] = ComponentHealth(
                    component_name=name,
                    status="unknown",
                    metrics=[],
                    last_check=datetime.now(),
                    error_count=1
                )
                alerts.append(f"Health check failed for {name}: {e}")
        
        # Determine overall system status
        statuses = [comp.status for comp in components.values()]
        if "critical" in statuses:
            overall_status = "critical"
        elif "warning" in statuses:
            overall_status = "warning"
        elif "unknown" in statuses:
            overall_status = "unknown"
        else:
            overall_status = "healthy"
        
        # Create system health object
        system_health = SystemHealth(
            overall_status=overall_status,
            components=components,
            system_metrics=[],
            timestamp=datetime.now(),
            alerts=alerts
        )
        
        # Add to history
        self.health_history.append(system_health)
        if len(self.health_history) > self.max_history_size:
            self.health_history.pop(0)
        
        return system_health
    
    def start_monitoring(self):
        """Start continuous health monitoring"""
        if self.running:
            logger.warning("Health monitoring already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"Health monitoring started (interval: {self.check_interval}s)")
    
    def stop_monitoring(self):
        """Stop health monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("Health monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                system_health = self.check_all_components()
                
                # Log overall status
                if system_health.overall_status != "healthy":
                    logger.warning(f"System health: {system_health.overall_status}")
                    for alert in system_health.alerts:
                        logger.warning(f"Alert: {alert}")
                else:
                    logger.debug("System health: healthy")
                
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
            
            # Wait for next check
            time.sleep(self.check_interval)
    
    def get_current_health(self) -> Optional[SystemHealth]:
        """Get current system health"""
        if self.health_history:
            return self.health_history[-1]
        return None
    
    def get_health_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get health summary for the specified time period
        
        Args:
            hours: Number of hours to include in summary
            
        Returns:
            Health summary dictionary
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_health = [h for h in self.health_history if h.timestamp >= cutoff_time]
        
        if not recent_health:
            return {"error": "No health data available for the specified period"}
        
        # Calculate uptime percentage
        total_checks = len(recent_health)
        healthy_checks = len([h for h in recent_health if h.overall_status == "healthy"])
        uptime_percentage = (healthy_checks / total_checks) * 100 if total_checks > 0 else 0
        
        # Component statistics
        component_stats = {}
        for component_name in self.checkers.keys():
            component_health_data = [h.components.get(component_name) for h in recent_health if h.components.get(component_name)]
            
            if component_health_data:
                healthy_count = len([c for c in component_health_data if c.status == "healthy"])
                component_uptime = (healthy_count / len(component_health_data)) * 100
                
                component_stats[component_name] = {
                    "uptime_percentage": component_uptime,
                    "total_checks": len(component_health_data),
                    "healthy_checks": healthy_count,
                    "current_status": component_health_data[-1].status
                }
        
        return {
            "period_hours": hours,
            "total_checks": total_checks,
            "overall_uptime_percentage": uptime_percentage,
            "current_status": recent_health[-1].overall_status,
            "component_statistics": component_stats,
            "recent_alerts": recent_health[-1].alerts if recent_health else []
        }
    
    def export_health_data(self, output_path: str):
        """
        Export health data to JSON file
        
        Args:
            output_path: Path to save health data
        """
        try:
            health_data = {
                "export_timestamp": datetime.now().isoformat(),
                "health_history": [asdict(h) for h in self.health_history]
            }
            
            with open(output_path, 'w') as f:
                json.dump(health_data, f, indent=2, default=str)
            
            logger.info(f"Health data exported to {output_path}")
            
        except Exception as e:
            logger.error(f"Error exporting health data: {e}")
            raise


def main():
    """Main function for health monitoring"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhanced Analysis Health Monitor'
    )
    parser.add_argument('--interval', type=int, default=60,
                       help='Health check interval in seconds')
    parser.add_argument('--check-once', action='store_true',
                       help='Run health check once and exit')
    parser.add_argument('--export', help='Export health data to file')
    parser.add_argument('--summary', type=int, metavar='HOURS',
                       help='Show health summary for specified hours')
    
    args = parser.parse_args()
    
    # Create health monitor
    monitor = EnhancedHealthMonitor(check_interval=args.interval)
    
    if args.check_once:
        # Run single health check
        system_health = monitor.check_all_components()
        print(json.dumps(asdict(system_health), indent=2, default=str))
        
        if system_health.overall_status != "healthy":
            sys.exit(1)
    
    elif args.summary:
        # Show health summary
        summary = monitor.get_health_summary(hours=args.summary)
        print(json.dumps(summary, indent=2))
    
    elif args.export:
        # Export health data
        monitor.export_health_data(args.export)
    
    else:
        # Start continuous monitoring
        try:
            monitor.start_monitoring()
            
            # Keep running until interrupted
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Shutting down health monitor...")
            monitor.stop_monitoring()


if __name__ == "__main__":
    main()