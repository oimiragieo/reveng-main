#!/usr/bin/env python3
"""
Enhanced Configuration Manager
=============================

Configuration management system for AI-Enhanced Universal Analysis Engine.
Handles configuration for AI services, analysis modules, and deployment settings.

Author: REVENG Project - Enhanced Configuration Module
Version: 1.0
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
import os

logger = logging.getLogger(__name__)


@dataclass
class AIServiceConfig:
    """Configuration for AI services"""
    provider: str = "ollama"  # ollama, openai, anthropic, local
    model: str = "auto"
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    timeout: int = 300
    max_retries: int = 3
    temperature: float = 0.1
    max_tokens: int = 4096


@dataclass
class AnalysisModuleConfig:
    """Configuration for individual analysis modules"""
    enabled: bool = True
    timeout: int = 300
    max_functions: int = 100
    confidence_threshold: float = 0.7
    output_formats: List[str] = None
    custom_settings: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.output_formats is None:
            self.output_formats = ["json"]
        if self.custom_settings is None:
            self.custom_settings = {}


@dataclass
class DeploymentConfig:
    """Configuration for deployment and infrastructure"""
    max_concurrent_analyses: int = 4
    temp_directory: str = "/tmp/reveng_enhanced"
    log_level: str = "INFO"
    log_retention_days: int = 30
    enable_metrics: bool = True
    metrics_port: int = 9090
    health_check_interval: int = 60
    resource_limits: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.resource_limits is None:
            self.resource_limits = {
                "max_memory_mb": 4096,
                "max_cpu_percent": 80,
                "max_disk_mb": 10240
            }


@dataclass
class SecurityConfig:
    """Security configuration for enhanced analysis"""
    enable_sandboxing: bool = True
    sandbox_timeout: int = 600
    allowed_file_types: List[str] = None
    max_file_size_mb: int = 100
    enable_network_isolation: bool = True
    quarantine_suspicious_files: bool = True
    
    def __post_init__(self):
        if self.allowed_file_types is None:
            self.allowed_file_types = [
                ".exe", ".dll", ".so", ".dylib", ".jar", ".war", ".ear", 
                ".class", ".pyc", ".pyo", ".js", ".wasm", ".bin", ".elf"
            ]


@dataclass
class EnhancedAnalysisConfiguration:
    """Complete configuration for enhanced analysis system"""
    # Core settings
    version: str = "1.0"
    enable_enhanced_analysis: bool = True
    
    # AI service configuration
    ai_service: AIServiceConfig = None
    
    # Module configurations
    corporate_exposure: AnalysisModuleConfig = None
    vulnerability_discovery: AnalysisModuleConfig = None
    threat_intelligence: AnalysisModuleConfig = None
    binary_reconstruction: AnalysisModuleConfig = None
    demonstration_generation: AnalysisModuleConfig = None
    
    # Infrastructure configuration
    deployment: DeploymentConfig = None
    security: SecurityConfig = None
    
    # Output and reporting
    output_directory: str = "enhanced_analysis_output"
    generate_executive_reports: bool = True
    generate_technical_reports: bool = True
    export_formats: List[str] = None
    
    def __post_init__(self):
        if self.ai_service is None:
            self.ai_service = AIServiceConfig()
        if self.corporate_exposure is None:
            self.corporate_exposure = AnalysisModuleConfig()
        if self.vulnerability_discovery is None:
            self.vulnerability_discovery = AnalysisModuleConfig()
        if self.threat_intelligence is None:
            self.threat_intelligence = AnalysisModuleConfig()
        if self.binary_reconstruction is None:
            self.binary_reconstruction = AnalysisModuleConfig()
        if self.demonstration_generation is None:
            self.demonstration_generation = AnalysisModuleConfig()
        if self.deployment is None:
            self.deployment = DeploymentConfig()
        if self.security is None:
            self.security = SecurityConfig()
        if self.export_formats is None:
            self.export_formats = ["json", "xml", "pdf"]


class EnhancedConfigManager:
    """
    Configuration manager for AI-Enhanced Universal Analysis Engine
    """
    
    DEFAULT_CONFIG_PATHS = [
        "enhanced_analysis_config.json",
        "config/enhanced_analysis.json",
        os.path.expanduser("~/.reveng/enhanced_config.json"),
        "/etc/reveng/enhanced_config.json"
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Optional path to configuration file
        """
        self.config_path = config_path
        self.config = EnhancedAnalysisConfiguration()
        self._load_configuration()
    
    def _load_configuration(self):
        """Load configuration from file"""
        config_file = self._find_config_file()
        
        if config_file:
            try:
                logger.info(f"Loading enhanced configuration from {config_file}")
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
                
                self._apply_config_data(config_data)
                logger.info("Enhanced configuration loaded successfully")
                
            except Exception as e:
                logger.warning(f"Error loading configuration from {config_file}: {e}")
                logger.info("Using default configuration")
        else:
            logger.info("No configuration file found, using defaults")
    
    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in default locations"""
        if self.config_path and Path(self.config_path).exists():
            return self.config_path
        
        for path in self.DEFAULT_CONFIG_PATHS:
            if Path(path).exists():
                return path
        
        return None
    
    def _apply_config_data(self, config_data: Dict[str, Any]):
        """Apply configuration data to config object"""
        # Update AI service configuration
        if 'ai_service' in config_data:
            ai_config = config_data['ai_service']
            for key, value in ai_config.items():
                if hasattr(self.config.ai_service, key):
                    setattr(self.config.ai_service, key, value)
        
        # Update module configurations
        modules = [
            'corporate_exposure', 'vulnerability_discovery', 'threat_intelligence',
            'binary_reconstruction', 'demonstration_generation'
        ]
        
        for module in modules:
            if module in config_data:
                module_config = config_data[module]
                config_obj = getattr(self.config, module)
                for key, value in module_config.items():
                    if hasattr(config_obj, key):
                        setattr(config_obj, key, value)
        
        # Update deployment configuration
        if 'deployment' in config_data:
            deploy_config = config_data['deployment']
            for key, value in deploy_config.items():
                if hasattr(self.config.deployment, key):
                    setattr(self.config.deployment, key, value)
        
        # Update security configuration
        if 'security' in config_data:
            security_config = config_data['security']
            for key, value in security_config.items():
                if hasattr(self.config.security, key):
                    setattr(self.config.security, key, value)
        
        # Update top-level settings
        top_level_keys = [
            'enable_enhanced_analysis', 'output_directory', 
            'generate_executive_reports', 'generate_technical_reports', 'export_formats'
        ]
        
        for key in top_level_keys:
            if key in config_data:
                setattr(self.config, key, config_data[key])
    
    def save_configuration(self, output_path: Optional[str] = None):
        """
        Save current configuration to file
        
        Args:
            output_path: Optional path to save configuration
        """
        save_path = output_path or self.config_path or "enhanced_analysis_config.json"
        
        try:
            # Ensure directory exists
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Save configuration
            with open(save_path, 'w') as f:
                json.dump(asdict(self.config), f, indent=2)
            
            logger.info(f"Configuration saved to {save_path}")
            
        except Exception as e:
            logger.error(f"Error saving configuration to {save_path}: {e}")
            raise
    
    def get_config(self) -> EnhancedAnalysisConfiguration:
        """Get current configuration"""
        return self.config
    
    def validate_configuration(self) -> List[str]:
        """
        Validate configuration and return list of issues
        
        Returns:
            List of validation error messages
        """
        issues = []
        
        # Validate AI service configuration
        if self.config.ai_service.provider not in ["ollama", "openai", "anthropic", "local"]:
            issues.append(f"Invalid AI provider: {self.config.ai_service.provider}")
        
        if self.config.ai_service.timeout <= 0:
            issues.append("AI service timeout must be positive")
        
        # Validate deployment configuration
        if self.config.deployment.max_concurrent_analyses <= 0:
            issues.append("Max concurrent analyses must be positive")
        
        if not Path(self.config.deployment.temp_directory).parent.exists():
            issues.append(f"Temp directory parent does not exist: {self.config.deployment.temp_directory}")
        
        # Validate security configuration
        if self.config.security.max_file_size_mb <= 0:
            issues.append("Max file size must be positive")
        
        if self.config.security.sandbox_timeout <= 0:
            issues.append("Sandbox timeout must be positive")
        
        # Validate module configurations
        modules = [
            self.config.corporate_exposure,
            self.config.vulnerability_discovery,
            self.config.threat_intelligence,
            self.config.binary_reconstruction,
            self.config.demonstration_generation
        ]
        
        for i, module in enumerate(modules):
            if module.timeout <= 0:
                issues.append(f"Module {i} timeout must be positive")
            
            if module.confidence_threshold < 0 or module.confidence_threshold > 1:
                issues.append(f"Module {i} confidence threshold must be between 0 and 1")
        
        return issues
    
    def create_default_config_file(self, output_path: str = "enhanced_analysis_config.json"):
        """
        Create a default configuration file with comments
        
        Args:
            output_path: Path to create the configuration file
        """
        default_config = {
            "_comment": "AI-Enhanced Universal Analysis Engine Configuration",
            "_version": "1.0",
            
            "enable_enhanced_analysis": True,
            
            "ai_service": {
                "_comment": "AI service configuration",
                "provider": "ollama",
                "model": "auto",
                "api_key": None,
                "api_url": None,
                "timeout": 300,
                "max_retries": 3,
                "temperature": 0.1,
                "max_tokens": 4096
            },
            
            "corporate_exposure": {
                "_comment": "Corporate data exposure analysis module",
                "enabled": True,
                "timeout": 300,
                "max_functions": 100,
                "confidence_threshold": 0.7,
                "output_formats": ["json", "xml"],
                "custom_settings": {
                    "scan_for_api_keys": True,
                    "scan_for_credentials": True,
                    "scan_for_business_logic": True
                }
            },
            
            "vulnerability_discovery": {
                "_comment": "Automated vulnerability discovery module",
                "enabled": True,
                "timeout": 300,
                "max_functions": 100,
                "confidence_threshold": 0.8,
                "output_formats": ["json", "sarif"],
                "custom_settings": {
                    "scan_memory_vulnerabilities": True,
                    "scan_injection_vulnerabilities": True,
                    "scan_crypto_vulnerabilities": True
                }
            },
            
            "threat_intelligence": {
                "_comment": "Threat intelligence correlation module",
                "enabled": True,
                "timeout": 300,
                "max_functions": 50,
                "confidence_threshold": 0.6,
                "output_formats": ["json", "stix"],
                "custom_settings": {
                    "enable_virustotal": True,
                    "enable_misp": False,
                    "enable_mitre_attack": True
                }
            },
            
            "binary_reconstruction": {
                "_comment": "Enhanced binary reconstruction module",
                "enabled": True,
                "timeout": 600,
                "max_functions": 200,
                "confidence_threshold": 0.9,
                "output_formats": ["source", "documentation"],
                "custom_settings": {
                    "generate_build_scripts": True,
                    "generate_documentation": True,
                    "create_test_cases": False
                }
            },
            
            "demonstration_generation": {
                "_comment": "Security demonstration generation module",
                "enabled": True,
                "timeout": 180,
                "max_functions": 50,
                "confidence_threshold": 0.7,
                "output_formats": ["html", "pdf", "pptx"],
                "custom_settings": {
                    "generate_executive_dashboard": True,
                    "generate_technical_report": True,
                    "generate_training_materials": True
                }
            },
            
            "deployment": {
                "_comment": "Deployment and infrastructure configuration",
                "max_concurrent_analyses": 4,
                "temp_directory": "/tmp/reveng_enhanced",
                "log_level": "INFO",
                "log_retention_days": 30,
                "enable_metrics": True,
                "metrics_port": 9090,
                "health_check_interval": 60,
                "resource_limits": {
                    "max_memory_mb": 4096,
                    "max_cpu_percent": 80,
                    "max_disk_mb": 10240
                }
            },
            
            "security": {
                "_comment": "Security configuration",
                "enable_sandboxing": True,
                "sandbox_timeout": 600,
                "allowed_file_types": [
                    ".exe", ".dll", ".so", ".dylib", ".jar", ".war", ".ear",
                    ".class", ".pyc", ".pyo", ".js", ".wasm", ".bin", ".elf"
                ],
                "max_file_size_mb": 100,
                "enable_network_isolation": True,
                "quarantine_suspicious_files": True
            },
            
            "output_directory": "enhanced_analysis_output",
            "generate_executive_reports": True,
            "generate_technical_reports": True,
            "export_formats": ["json", "xml", "pdf"]
        }
        
        try:
            with open(output_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            logger.info(f"Default configuration file created: {output_path}")
            
        except Exception as e:
            logger.error(f"Error creating default configuration file: {e}")
            raise


def get_enhanced_config(config_path: Optional[str] = None) -> EnhancedAnalysisConfiguration:
    """
    Get enhanced analysis configuration
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        EnhancedAnalysisConfiguration object
    """
    manager = EnhancedConfigManager(config_path)
    return manager.get_config()


def main():
    """Main function for configuration management"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhanced Configuration Manager for AI-Enhanced Universal Analysis Engine'
    )
    parser.add_argument('--create-default', action='store_true',
                       help='Create default configuration file')
    parser.add_argument('--validate', help='Validate configuration file')
    parser.add_argument('--output', default='enhanced_analysis_config.json',
                       help='Output path for configuration file')
    
    args = parser.parse_args()
    
    if args.create_default:
        manager = EnhancedConfigManager()
        manager.create_default_config_file(args.output)
        print(f"Default configuration file created: {args.output}")
        
    elif args.validate:
        if not Path(args.validate).exists():
            print(f"Configuration file not found: {args.validate}")
            return
        
        manager = EnhancedConfigManager(args.validate)
        issues = manager.validate_configuration()
        
        if issues:
            print("Configuration validation failed:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print("Configuration validation passed")
    
    else:
        print("Use --create-default to create a default configuration file")
        print("Use --validate <file> to validate a configuration file")


if __name__ == "__main__":
    main()