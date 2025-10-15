#!/usr/bin/env python3
"""
Enhanced Analysis Deployment Script
==================================

Deployment and setup script for AI-Enhanced Universal Analysis Engine.
Handles dependency installation, configuration setup, and health checks.

Author: REVENG Project - Deployment Module
Version: 1.0
"""

import os
import sys
import json
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import shutil
import platform

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EnhancedAnalysisDeployer:
    """
    Deployment manager for AI-Enhanced Universal Analysis Engine
    """
    
    def __init__(self, deployment_config: Optional[Dict[str, Any]] = None):
        """
        Initialize deployer
        
        Args:
            deployment_config: Optional deployment configuration
        """
        self.config = deployment_config or {}
        self.system = platform.system().lower()
        self.python_executable = sys.executable
        
        # Deployment paths
        self.base_dir = Path.cwd()
        self.tools_dir = self.base_dir / "tools"
        self.scripts_dir = self.base_dir / "scripts"
        self.config_dir = self.base_dir / "config"
        
        # Create directories
        self.config_dir.mkdir(exist_ok=True)
        
        logger.info(f"Enhanced Analysis Deployer initialized for {self.system}")
    
    def check_system_requirements(self) -> List[str]:
        """
        Check system requirements for enhanced analysis
        
        Returns:
            List of missing requirements
        """
        logger.info("Checking system requirements...")
        
        missing = []
        
        # Check Python version
        if sys.version_info < (3, 8):
            missing.append("Python 3.8 or higher required")
        
        # Check required Python packages
        required_packages = [
            "requests", "numpy", "pandas", "matplotlib", "seaborn",
            "pyyaml", "jinja2", "click", "tqdm", "psutil"
        ]
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing.append(f"Python package: {package}")
        
        # Check system tools
        system_tools = {
            "git": "Git version control",
            "curl": "HTTP client for API calls"
        }
        
        for tool, description in system_tools.items():
            if not shutil.which(tool):
                missing.append(f"System tool: {tool} ({description})")
        
        # Check optional tools
        optional_tools = {
            "docker": "Container runtime for sandboxing",
            "java": "Java runtime for bytecode analysis",
            "dotnet": ".NET runtime for assembly analysis"
        }
        
        for tool, description in optional_tools.items():
            if not shutil.which(tool):
                logger.warning(f"Optional tool not found: {tool} ({description})")
        
        if missing:
            logger.warning(f"Missing requirements: {missing}")
        else:
            logger.info("All system requirements satisfied")
        
        return missing
    
    def install_dependencies(self) -> bool:
        """
        Install required dependencies
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Installing dependencies...")
        
        try:
            # Install Python dependencies
            requirements_files = [
                "requirements.txt",
                "requirements-dev.txt"
            ]
            
            for req_file in requirements_files:
                if Path(req_file).exists():
                    logger.info(f"Installing from {req_file}")
                    result = subprocess.run([
                        self.python_executable, "-m", "pip", "install", "-r", req_file
                    ], capture_output=True, text=True)
                    
                    if result.returncode != 0:
                        logger.error(f"Failed to install from {req_file}: {result.stderr}")
                        return False
            
            # Install enhanced analysis specific dependencies
            enhanced_packages = [
                "yara-python",  # For malware detection
                "pefile",       # For PE file analysis
                "pyelftools",   # For ELF file analysis
                "python-magic", # For file type detection
                "cryptography", # For crypto analysis
                "networkx",     # For graph analysis
                "scikit-learn", # For ML-based analysis
                "plotly",       # For interactive visualizations
                "reportlab",    # For PDF generation
                "python-pptx"   # For PowerPoint generation
            ]
            
            for package in enhanced_packages:
                logger.info(f"Installing {package}")
                result = subprocess.run([
                    self.python_executable, "-m", "pip", "install", package
                ], capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.warning(f"Failed to install {package}: {result.stderr}")
            
            logger.info("Dependencies installation completed")
            return True
            
        except Exception as e:
            logger.error(f"Error installing dependencies: {e}")
            return False
    
    def setup_configuration(self) -> bool:
        """
        Setup configuration files
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Setting up configuration...")
        
        try:
            # Create enhanced analysis configuration
            from tools.enhanced_config_manager import EnhancedConfigManager
            
            config_manager = EnhancedConfigManager()
            config_path = self.config_dir / "enhanced_analysis.json"
            
            if not config_path.exists():
                config_manager.create_default_config_file(str(config_path))
                logger.info(f"Created default configuration: {config_path}")
            else:
                logger.info(f"Configuration already exists: {config_path}")
            
            # Validate configuration
            issues = config_manager.validate_configuration()
            if issues:
                logger.warning("Configuration validation issues:")
                for issue in issues:
                    logger.warning(f"  - {issue}")
            else:
                logger.info("Configuration validation passed")
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting up configuration: {e}")
            return False
    
    def setup_directories(self) -> bool:
        """
        Setup required directories
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Setting up directories...")
        
        try:
            # Create required directories
            directories = [
                "enhanced_analysis_output",
                "temp/enhanced_analysis",
                "logs/enhanced_analysis",
                "cache/enhanced_analysis",
                "quarantine"
            ]
            
            for directory in directories:
                dir_path = self.base_dir / directory
                dir_path.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created directory: {dir_path}")
            
            # Set permissions (Unix-like systems)
            if self.system in ["linux", "darwin"]:
                temp_dir = self.base_dir / "temp/enhanced_analysis"
                os.chmod(temp_dir, 0o755)
                
                quarantine_dir = self.base_dir / "quarantine"
                os.chmod(quarantine_dir, 0o700)  # Restricted access
            
            logger.info("Directory setup completed")
            return True
            
        except Exception as e:
            logger.error(f"Error setting up directories: {e}")
            return False
    
    def setup_logging(self) -> bool:
        """
        Setup logging configuration
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Setting up logging configuration...")
        
        try:
            log_config = {
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                    },
                    "detailed": {
                        "format": "%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s"
                    }
                },
                "handlers": {
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout"
                    },
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "DEBUG",
                        "formatter": "detailed",
                        "filename": "logs/enhanced_analysis/enhanced_analysis.log",
                        "maxBytes": 10485760,
                        "backupCount": 5
                    },
                    "error_file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "ERROR",
                        "formatter": "detailed",
                        "filename": "logs/enhanced_analysis/errors.log",
                        "maxBytes": 10485760,
                        "backupCount": 5
                    }
                },
                "loggers": {
                    "": {
                        "handlers": ["console", "file", "error_file"],
                        "level": "DEBUG",
                        "propagate": False
                    }
                }
            }
            
            # Save logging configuration
            log_config_path = self.config_dir / "logging.json"
            with open(log_config_path, 'w') as f:
                json.dump(log_config, f, indent=2)
            
            logger.info(f"Logging configuration saved: {log_config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error setting up logging: {e}")
            return False
    
    def run_health_checks(self) -> Dict[str, bool]:
        """
        Run health checks for enhanced analysis components
        
        Returns:
            Dictionary of component health status
        """
        logger.info("Running health checks...")
        
        health_status = {}
        
        # Check core REVENG components
        core_modules = [
            "tools.language_detector",
            "tools.config_manager",
            "reveng_analyzer"
        ]
        
        for module in core_modules:
            try:
                __import__(module)
                health_status[f"core_{module.split('.')[-1]}"] = True
                logger.debug(f"Core module OK: {module}")
            except ImportError as e:
                health_status[f"core_{module.split('.')[-1]}"] = False
                logger.warning(f"Core module failed: {module} - {e}")
        
        # Check enhanced analysis modules
        enhanced_modules = [
            "tools.ai_enhanced_analyzer",
            "tools.corporate_exposure_detector",
            "tools.vulnerability_discovery_engine",
            "tools.threat_intelligence_correlator",
            "tools.demonstration_generator"
        ]
        
        for module in enhanced_modules:
            try:
                __import__(module)
                health_status[f"enhanced_{module.split('.')[-1]}"] = True
                logger.debug(f"Enhanced module OK: {module}")
            except ImportError as e:
                health_status[f"enhanced_{module.split('.')[-1]}"] = False
                logger.warning(f"Enhanced module failed: {module} - {e}")
        
        # Check AI service availability
        try:
            from tools.ollama_preflight import OllamaPreflightChecker
            checker = OllamaPreflightChecker()
            success, _ = checker.check_all()
            health_status["ai_service_ollama"] = success
        except Exception as e:
            health_status["ai_service_ollama"] = False
            logger.warning(f"AI service check failed: {e}")
        
        # Check file system permissions
        try:
            test_file = self.base_dir / "temp/enhanced_analysis/health_check.txt"
            test_file.write_text("health check")
            test_file.unlink()
            health_status["filesystem_permissions"] = True
        except Exception as e:
            health_status["filesystem_permissions"] = False
            logger.warning(f"Filesystem permissions check failed: {e}")
        
        # Summary
        passed = sum(health_status.values())
        total = len(health_status)
        logger.info(f"Health checks completed: {passed}/{total} passed")
        
        return health_status
    
    def create_service_scripts(self) -> bool:
        """
        Create service scripts for deployment
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Creating service scripts...")
        
        try:
            # Create startup script
            startup_script = self.scripts_dir / "start_enhanced_analysis.py"
            startup_content = '''#!/usr/bin/env python3
"""
Enhanced Analysis Startup Script
"""

import sys
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tools.enhanced_config_manager import get_enhanced_config
from reveng_analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures

def main():
    """Start enhanced analysis service"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting AI-Enhanced Universal Analysis Engine")
    
    # Load configuration
    config = get_enhanced_config()
    
    # Create enhanced features from config
    features = EnhancedAnalysisFeatures()
    features.enable_enhanced_analysis = config.enable_enhanced_analysis
    features.enable_corporate_exposure = config.corporate_exposure.enabled
    features.enable_vulnerability_discovery = config.vulnerability_discovery.enabled
    features.enable_threat_intelligence = config.threat_intelligence.enabled
    features.enable_enhanced_reconstruction = config.binary_reconstruction.enabled
    features.enable_demonstration_generation = config.demonstration_generation.enabled
    
    logger.info("Enhanced analysis engine ready")
    logger.info(f"Enabled modules: {features}")

if __name__ == "__main__":
    main()
'''
            
            with open(startup_script, 'w') as f:
                f.write(startup_content)
            
            # Make executable on Unix-like systems
            if self.system in ["linux", "darwin"]:
                os.chmod(startup_script, 0o755)
            
            # Create health check script
            health_script = self.scripts_dir / "health_check_enhanced.py"
            health_content = '''#!/usr/bin/env python3
"""
Enhanced Analysis Health Check Script
"""

import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from scripts.deploy_enhanced_analysis import EnhancedAnalysisDeployer

def main():
    """Run health checks"""
    deployer = EnhancedAnalysisDeployer()
    health_status = deployer.run_health_checks()
    
    # Output results
    print(json.dumps(health_status, indent=2))
    
    # Exit with error code if any checks failed
    if not all(health_status.values()):
        sys.exit(1)

if __name__ == "__main__":
    main()
'''
            
            with open(health_script, 'w') as f:
                f.write(health_content)
            
            # Make executable on Unix-like systems
            if self.system in ["linux", "darwin"]:
                os.chmod(health_script, 0o755)
            
            logger.info("Service scripts created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error creating service scripts: {e}")
            return False
    
    def deploy(self) -> bool:
        """
        Run complete deployment process
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Starting enhanced analysis deployment...")
        
        steps = [
            ("Checking system requirements", self.check_system_requirements),
            ("Installing dependencies", self.install_dependencies),
            ("Setting up directories", self.setup_directories),
            ("Setting up configuration", self.setup_configuration),
            ("Setting up logging", self.setup_logging),
            ("Creating service scripts", self.create_service_scripts),
            ("Running health checks", self.run_health_checks)
        ]
        
        for step_name, step_func in steps:
            logger.info(f"Step: {step_name}")
            
            try:
                if step_name == "Checking system requirements":
                    missing = step_func()
                    if missing:
                        logger.error(f"Missing requirements: {missing}")
                        return False
                elif step_name == "Running health checks":
                    health_status = step_func()
                    if not all(health_status.values()):
                        logger.warning("Some health checks failed, but deployment continues")
                else:
                    result = step_func()
                    if not result:
                        logger.error(f"Step failed: {step_name}")
                        return False
                
                logger.info(f"Step completed: {step_name}")
                
            except Exception as e:
                logger.error(f"Step failed with exception: {step_name} - {e}")
                return False
        
        logger.info("Enhanced analysis deployment completed successfully!")
        logger.info("You can now run: python reveng_analyzer.py <binary_path>")
        
        return True


def main():
    """Main deployment function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Deploy AI-Enhanced Universal Analysis Engine'
    )
    parser.add_argument('--config', help='Deployment configuration file')
    parser.add_argument('--health-check-only', action='store_true',
                       help='Run health checks only')
    parser.add_argument('--install-deps-only', action='store_true',
                       help='Install dependencies only')
    
    args = parser.parse_args()
    
    # Load deployment configuration if provided
    deployment_config = None
    if args.config and Path(args.config).exists():
        with open(args.config, 'r') as f:
            deployment_config = json.load(f)
    
    deployer = EnhancedAnalysisDeployer(deployment_config)
    
    if args.health_check_only:
        health_status = deployer.run_health_checks()
        print(json.dumps(health_status, indent=2))
        if not all(health_status.values()):
            sys.exit(1)
    
    elif args.install_deps_only:
        success = deployer.install_dependencies()
        if not success:
            sys.exit(1)
    
    else:
        success = deployer.deploy()
        if not success:
            sys.exit(1)


if __name__ == "__main__":
    main()